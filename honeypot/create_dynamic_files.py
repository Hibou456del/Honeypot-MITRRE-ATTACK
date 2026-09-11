"""
Dynamic decoy file generator for the Dynamic Honeypot Platform.
Generates fake files, users, credentials, and other decoy elements.
"""

import json
import random
import string
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from utils.logger import get_logger
from utils.config_loader import ConfigLoader
from utils.file_utils import FileUtils


@dataclass
class FakeUser:
    """Fake user structure."""
    username: str
    password: str
    uid: int
    gid: int
    home_dir: str
    shell: str
    full_name: str
    role: str


@dataclass
class FakeCredential:
    """Fake credential structure."""
    service: str
    username: str
    password: str
    api_key: str
    description: str


@dataclass
class DecoyGenerationResult:
    """Result of decoy generation."""
    profile: str
    timestamp: str
    files_created: List[str]
    users_created: List[str]
    credentials_created: List[str]
    directories_created: List[str]
    total_files: int
    total_users: int
    total_credentials: int


class DynamicDecoyGenerator:
    """Generates dynamic decoy files and configurations."""
    
    def __init__(self, config_dir: str = "config", output_dir: str = "data/generated_decoys"):
        """
        Initialize decoy generator.
        
        Args:
            config_dir: Directory containing configuration files
            output_dir: Directory for generated decoys
        """
        self.config_loader = ConfigLoader(config_dir)
        self.output_dir = Path(output_dir)
        self.logger = get_logger("DynamicDecoyGenerator")
        FileUtils.ensure_dir(self.output_dir)
        
        # Load configuration
        self.profiles_config = self.config_loader.load_yaml("honeypot_profiles.yaml")
        self.settings = self.config_loader.load_settings("settings.yaml")
        
        # Template directory
        self.template_dir = Path("honeypot/decoy_templates")
    
    def generate_decoys_for_profile(self, profile_name: str) -> DecoyGenerationResult:
        """
        Generate decoys for a specific profile.
        
        Args:
            profile_name: Name of the profile (e.g., PROFILE_LOW)
            
        Returns:
            DecoyGenerationResult with generation details
        """
        self.logger.info(f"Generating decoys for profile: {profile_name}")
        
        profile_config = self.profiles_config['profiles'].get(profile_name)
        if not profile_config:
            self.logger.error(f"Profile not found: {profile_name}")
            raise ValueError(f"Profile not found: {profile_name}")
        
        result = DecoyGenerationResult(
            profile=profile_name,
            timestamp=datetime.now().isoformat(),
            files_created=[],
            users_created=[],
            credentials_created=[],
            directories_created=[],
            total_files=0,
            total_users=0,
            total_credentials=0
        )
        
        # Create profile-specific directory
        profile_dir = self.output_dir / profile_name.lower()
        FileUtils.ensure_dir(profile_dir)
        result.directories_created.append(str(profile_dir))
        
        # Generate decoys based on profile configuration
        for decoy_config in profile_config.get('decoys', []):
            decoy_type = decoy_config.get('type')
            
            if decoy_type == 'users':
                users = self._generate_fake_users(decoy_config, profile_dir)
                result.users_created.extend([u.username for u in users])
                result.total_users += len(users)
            
            elif decoy_type == 'directories':
                directories = self._generate_fake_directories(decoy_config, profile_dir)
                result.directories_created.extend(directories)
            
            elif decoy_type == 'files':
                files = self._generate_fake_files(decoy_config, profile_dir)
                result.files_created.extend(files)
                result.total_files += len(files)
            
            elif decoy_type == 'fake_credentials':
                credentials = self._generate_fake_credentials(decoy_config, profile_dir)
                result.credentials_created.extend([f"{c.service}:{c.username}" for c in credentials])
                result.total_credentials += len(credentials)
            
            elif decoy_type == 'fake_web_files':
                files = self._generate_fake_web_files(decoy_config, profile_dir)
                result.files_created.extend(files)
                result.total_files += len(files)
            
            elif decoy_type == 'fake_database':
                database_file = self._generate_fake_database(decoy_config, profile_dir)
                if database_file:
                    result.files_created.append(database_file)
                    result.total_files += 1
        
        # Save generation metadata
        self._save_generation_metadata(result, profile_dir)
        
        self.logger.info(
            f"Generated {result.total_files} files, {result.total_users} users, "
            f"{result.total_credentials} credentials for profile {profile_name}"
        )
        
        return result
    
    def _generate_fake_users(self, config: Dict[str, Any], base_dir: Path) -> List[FakeUser]:
        """Generate fake user accounts."""
        count = config.get('count', 5)
        names = config.get('names', [])
        
        users = []
        for i in range(count):
            if i < len(names):
                username = names[i]
            else:
                username = f"fake_user_{i}"
            
            user = FakeUser(
                username=username,
                password=self._generate_fake_password(),
                uid=random.randint(1000, 9999),
                gid=random.randint(1000, 9999),
                home_dir=f"/home/{username}",
                shell="/bin/bash",
                full_name=f"Fake {username.capitalize()}",
                role="user"
            )
            users.append(user)
        
        # Save users to JSON file
        users_file = base_dir / "fake_users.json"
        users_data = [asdict(user) for user in users]
        FileUtils.save_json(users_file, users_data)
        
        # Generate fake /etc/passwd style file
        passwd_file = base_dir / "etc_passwd"
        passwd_content = ""
        for user in users:
            passwd_content += f"{user.username}:x:{user.uid}:{user.gid}:{user.full_name}:{user.home_dir}:{user.shell}\n"
        FileUtils.safe_write(passwd_file, passwd_content)
        
        return users
    
    def _generate_fake_credentials(self, config: Dict[str, Any], base_dir: Path) -> List[FakeCredential]:
        """Generate fake credentials."""
        count = config.get('count', 10)
        formats = config.get('formats', ['env', 'config', 'txt'])
        
        credentials = []
        services = ['database', 'api', 'backup', 'email', 'storage', 'monitoring']
        
        for i in range(count):
            service = services[i % len(services)]
            credential = FakeCredential(
                service=service,
                username=f"fake_{service}_user",
                password=self._generate_fake_password(),
                api_key=self._generate_fake_api_key(),
                description=f"Fake credentials for {service} service"
            )
            credentials.append(credential)
        
        # Save credentials in different formats
        for format_type in formats:
            if format_type == 'env':
                self._save_credentials_as_env(credentials, base_dir / "credentials.env")
            elif format_type == 'config':
                self._save_credentials_as_config(credentials, base_dir / "credentials.json")
            elif format_type == 'txt':
                self._save_credentials_as_txt(credentials, base_dir / "credentials.txt")
        
        return credentials
    
    def _generate_fake_directories(self, config: Dict[str, Any], base_dir: Path) -> List[str]:
        """Generate fake directory structure."""
        paths = config.get('paths', [])
        created_dirs = []
        
        for path in paths:
            # Create directory under base directory
            dir_path = base_dir / path.lstrip('/')
            FileUtils.ensure_dir(dir_path)
            created_dirs.append(str(dir_path))
        
        return created_dirs
    
    def _generate_fake_files(self, config: Dict[str, Any], base_dir: Path) -> List[str]:
        """Generate fake files."""
        count = config.get('count', 10)
        locations = config.get('locations', ['/tmp'])
        include_configs = config.get('include_configs', False)
        include_credentials = config.get('include_credentials', False)
        
        created_files = []
        
        for i in range(count):
            location = locations[i % len(locations)]
            location_dir = base_dir / location.lstrip('/')
            FileUtils.ensure_dir(location_dir)
            
            # Generate different types of files
            file_type = random.choice(['log', 'data', 'config', 'script'])
            
            if file_type == 'log':
                filename = f"fake_log_{i}.log"
                content = self._generate_fake_log_content()
            elif file_type == 'data':
                filename = f"fake_data_{i}.json"
                content = json.dumps(self._generate_fake_data(), indent=2)
            elif file_type == 'config':
                filename = f"fake_config_{i}.conf"
                content = self._generate_fake_config_content()
            else:  # script
                filename = f"fake_script_{i}.sh"
                content = self._generate_fake_script_content()
            
            file_path = location_dir / filename
            FileUtils.safe_write(file_path, content)
            created_files.append(str(file_path))
        
        # Add configuration files if requested
        if include_configs:
            self._add_config_templates(base_dir, created_files)
        
        # Add credential files if requested
        if include_credentials:
            self._add_credential_templates(base_dir, created_files)
        
        return created_files
    
    def _generate_fake_web_files(self, config: Dict[str, Any], base_dir: Path) -> List[str]:
        """Generate fake web files."""
        count = config.get('count', 15)
        types = config.get('types', ['php', 'html', 'js', 'sql'])
        
        created_files = []
        
        # Create web directory structure
        web_dir = base_dir / "var/www"
        FileUtils.ensure_dir(web_dir)
        
        for i in range(count):
            file_type = types[i % len(types)]
            filename = f"fake_{file_type}_{i}.{file_type}"
            
            if file_type == 'php':
                content = self._generate_fake_php_content()
            elif file_type == 'html':
                content = self._generate_fake_html_content()
            elif file_type == 'js':
                content = self._generate_fake_js_content()
            else:  # sql
                content = self._generate_fake_sql_content()
            
            file_path = web_dir / filename
            FileUtils.safe_write(file_path, content)
            created_files.append(str(file_path))
        
        return created_files
    
    def _generate_fake_database(self, config: Dict[str, Any], base_dir: Path) -> Optional[str]:
        """Generate fake database SQL file."""
        tables = config.get('tables', 10)
        rows_per_table = config.get('rows_per_table', 50)
        
        db_content = "-- Fake database for honeypot\n-- All data is fictional\n\n"
        
        for i in range(tables):
            table_name = f"fake_table_{i}"
            db_content += f"CREATE TABLE {table_name} (\n"
            db_content += "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            db_content += "    name VARCHAR(100),\n"
            db_content += "    value TEXT,\n"
            db_content += "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
            db_content += ");\n\n"
            
            # Add fake data
            for j in range(rows_per_table):
                db_content += f"INSERT INTO {table_name} (name, value) VALUES "
                db_content += f"('fake_name_{j}', 'fake_value_{random.randint(1000, 9999)}');\n"
            db_content += "\n"
        
        db_file = base_dir / "fake_database.sql"
        FileUtils.safe_write(db_file, db_content)
        
        return str(db_file)
    
    def _generate_fake_password(self, length: int = 16) -> str:
        """Generate fake password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_fake_api_key(self, length: int = 32) -> str:
        """Generate fake API key."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_fake_log_content(self) -> str:
        """Generate fake log content."""
        timestamps = []
        for i in range(10):
            timestamp = datetime.now().isoformat()
            level = random.choice(['INFO', 'WARNING', 'ERROR', 'DEBUG'])
            message = f"Fake log message {i} for deception purposes"
            timestamps.append(f"{timestamp} - {level} - {message}\n")
        return ''.join(timestamps)
    
    def _generate_fake_data(self) -> Dict[str, Any]:
        """Generate fake JSON data."""
        return {
            "id": random.randint(1000, 9999),
            "name": f"fake_item_{random.randint(100, 999)}",
            "value": random.random() * 100,
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "honeypot_decoy",
                "fake": True
            }
        }
    
    def _generate_fake_config_content(self) -> str:
        """Generate fake configuration content."""
        return f"""# Fake configuration file
# Generated by honeypot decoy generator

setting1=fake_value_{random.randint(100, 999)}
setting2=fake_value_{random.randint(100, 999)}
enabled=true
timeout={random.randint(30, 300)}
debug=false

# Fake credentials
username=fake_user_{random.randint(100, 999)}
password={self._generate_fake_password()}
api_key={self._generate_fake_api_key()}
"""
    
    def _generate_fake_script_content(self) -> str:
        """Generate fake script content."""
        return """#!/bin/bash
# Fake script for honeypot decoy

echo "Fake script execution"
FAKE_VAR="fake_value_123"
echo $FAKE_VAR

# Fake operations
fake_command() {
    echo "Executing fake command"
}

fake_command
exit 0
"""
    
    def _generate_fake_php_content(self) -> str:
        """Generate fake PHP content."""
        return """<?php
// Fake PHP file for honeypot decoy
$fake_var = "fake_value_123";
$fake_config = array(
    'db_host' => 'localhost',
    'db_user' => 'fake_user',
    'db_pass' => 'fake_password'
);

function fake_function() {
    return "fake_result";
}

echo fake_function();
?>"""
    
    def _generate_fake_html_content(self) -> str:
        """Generate fake HTML content."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Fake Page</title>
</head>
<body>
    <h1>Fake Content</h1>
    <p>This is a decoy page for honeypot purposes.</p>
    <div class="fake-content">
        <p>Fake data: 12345</p>
    </div>
</body>
</html>"""
    
    def _generate_fake_js_content(self) -> str:
        """Generate fake JavaScript content."""
        return """// Fake JavaScript for honeypot decoy
var fakeConfig = {
    apiKey: 'fake_key_123',
    endpoint: 'https://fake.example.com/api'
};

function fakeFunction() {
    console.log('Fake function execution');
    return 'fake_result';
}

fakeFunction();"""
    
    def _generate_fake_sql_content(self) -> str:
        """Generate fake SQL content."""
        return """-- Fake SQL for honeypot decoy
SELECT * FROM fake_table WHERE id = 123;
INSERT INTO fake_table (name, value) VALUES ('fake', 'decoy');
UPDATE fake_table SET value = 'updated' WHERE id = 123;
DELETE FROM fake_table WHERE id = 999;"""
    
    def _save_credentials_as_env(self, credentials: List[FakeCredential], file_path: Path):
        """Save credentials in .env format."""
        content = "# Fake credentials file\n"
        for cred in credentials:
            content += f"{cred.service.upper()}_USER={cred.username}\n"
            content += f"{cred.service.upper()}_PASSWORD={cred.password}\n"
            content += f"{cred.service.upper()}_API_KEY={cred.api_key}\n\n"
        FileUtils.safe_write(file_path, content)
    
    def _save_credentials_as_config(self, credentials: List[FakeCredential], file_path: Path):
        """Save credentials in JSON config format."""
        credentials_data = [asdict(cred) for cred in credentials]
        FileUtils.save_json(file_path, credentials_data)
    
    def _save_credentials_as_txt(self, credentials: List[FakeCredential], file_path: Path):
        """Save credentials in plain text format."""
        content = "# Fake credentials file\n"
        for cred in credentials:
            content += f"Service: {cred.service}\n"
            content += f"Username: {cred.username}\n"
            content += f"Password: {cred.password}\n"
            content += f"API Key: {cred.api_key}\n"
            content += f"Description: {cred.description}\n\n"
        FileUtils.safe_write(file_path, content)
    
    def _add_config_templates(self, base_dir: Path, created_files: List[str]):
        """Add configuration templates from template directory."""
        if self.template_dir.exists():
            for template_file in self.template_dir.glob("*"):
                if template_file.is_file():
                    dest_file = base_dir / template_file.name
                    FileUtils.copy_file(template_file, dest_file)
                    created_files.append(str(dest_file))
    
    def _add_credential_templates(self, base_dir: Path, created_files: List[str]):
        """Add credential templates."""
        # Create .env file
        env_file = base_dir / ".env"
        env_content = f"""# Fake environment file
DB_HOST=localhost
DB_USER=fake_user
DB_PASSWORD={self._generate_fake_password()}
API_KEY={self._generate_fake_api_key()}
SECRET_KEY={self._generate_fake_password()}
"""
        FileUtils.safe_write(env_file, env_content)
        created_files.append(str(env_file))
    
    def _save_generation_metadata(self, result: DecoyGenerationResult, profile_dir: Path):
        """Save generation metadata."""
        metadata_file = profile_dir / "generation_metadata.json"
        FileUtils.save_json(metadata_file, asdict(result))


def generate_decoys(profile_name: str = "PROFILE_LOW") -> DecoyGenerationResult:
    """
    Convenience function to generate decoys for a profile.
    
    Args:
        profile_name: Name of the profile
        
    Returns:
        DecoyGenerationResult
    """
    generator = DynamicDecoyGenerator()
    return generator.generate_decoys_for_profile(profile_name)


if __name__ == "__main__":
    # Generate decoys for default profile
    result = generate_decoys("PROFILE_LOW")
    print(f"Generated decoys: {result}")