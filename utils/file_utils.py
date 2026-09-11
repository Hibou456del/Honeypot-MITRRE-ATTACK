"""
File utilities for the Dynamic Honeypot Platform.
Provides cross-platform file operations and path handling.
"""

import os
import shutil
from pathlib import Path
from typing import List, Optional, Union
import json
import hashlib


class FileUtils:
    """Cross-platform file operations utility."""
    
    @staticmethod
    def ensure_dir(path: Union[str, Path]) -> Path:
        """
        Ensure directory exists, create if it doesn't.
        
        Args:
            path: Directory path
            
        Returns:
            Path object
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @staticmethod
    def safe_write(path: Union[str, Path], content: str, encoding: str = 'utf-8') -> None:
        """
        Safely write content to file.
        
        Args:
            path: File path
            content: Content to write
            encoding: File encoding
        """
        path = Path(path)
        FileUtils.ensure_dir(path.parent)
        
        with open(path, 'w', encoding=encoding) as f:
            f.write(content)
    
    @staticmethod
    def safe_read(path: Union[str, Path], encoding: str = 'utf-8') -> Optional[str]:
        """
        Safely read file content.
        
        Args:
            path: File path
            encoding: File encoding
            
        Returns:
            File content or None if file doesn't exist
        """
        path = Path(path)
        if not path.exists():
            return None
        
        with open(path, 'r', encoding=encoding) as f:
            return f.read()
    
    @staticmethod
    def safe_delete(path: Union[str, Path]) -> bool:
        """
        Safely delete file or directory.
        
        Args:
            path: File or directory path
            
        Returns:
            True if deleted, False otherwise
        """
        path = Path(path)
        if not path.exists():
            return False
        
        try:
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
            return True
        except Exception:
            return False
    
    @staticmethod
    def list_files(
        directory: Union[str, Path],
        pattern: str = "*",
        recursive: bool = False
    ) -> List[Path]:
        """
        List files in directory matching pattern.
        
        Args:
            directory: Directory path
            pattern: File pattern (e.g., "*.log")
            recursive: Whether to search recursively
            
        Returns:
            List of Path objects
        """
        directory = Path(directory)
        if not directory.exists():
            return []
        
        if recursive:
            return list(directory.rglob(pattern))
        else:
            return list(directory.glob(pattern))
    
    @staticmethod
    def get_file_hash(path: Union[str, Path], algorithm: str = 'sha256') -> str:
        """
        Calculate file hash.
        
        Args:
            path: File path
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hexadecimal hash string
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        hash_func = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def get_file_size(path: Union[str, Path]) -> int:
        """
        Get file size in bytes.
        
        Args:
            path: File path
            
        Returns:
            File size in bytes
        """
        path = Path(path)
        if not path.exists():
            return 0
        
        return path.stat().st_size
    
    @staticmethod
    def is_text_file(path: Union[str, Path]) -> bool:
        """
        Check if file is likely a text file.
        
        Args:
            path: File path
            
        Returns:
            True if likely text file
        """
        path = Path(path)
        if not path.exists() or not path.is_file():
            return False
        
        # Check common text file extensions
        text_extensions = {
            '.txt', '.log', '.json', '.yaml', '.yml', '.xml',
            '.csv', '.md', '.py', '.js', '.html', '.css', '.php',
            '.sql', '.sh', '.bash', '.env', '.conf', '.config'
        }
        
        return path.suffix.lower() in text_extensions
    
    @staticmethod
    def copy_file(
        source: Union[str, Path],
        destination: Union[str, Path],
        overwrite: bool = False
    ) -> bool:
        """
        Copy file from source to destination.
        
        Args:
            source: Source file path
            destination: Destination file path
            overwrite: Whether to overwrite existing file
            
        Returns:
            True if successful
        """
        source = Path(source)
        destination = Path(destination)
        
        if not source.exists():
            return False
        
        if destination.exists() and not overwrite:
            return False
        
        FileUtils.ensure_dir(destination.parent)
        shutil.copy2(source, destination)
        return True
    
    @staticmethod
    def move_file(
        source: Union[str, Path],
        destination: Union[str, Path],
        overwrite: bool = False
    ) -> bool:
        """
        Move file from source to destination.
        
        Args:
            source: Source file path
            destination: Destination file path
            overwrite: Whether to overwrite existing file
            
        Returns:
            True if successful
        """
        source = Path(source)
        destination = Path(destination)
        
        if not source.exists():
            return False
        
        if destination.exists() and not overwrite:
            return False
        
        FileUtils.ensure_dir(destination.parent)
        shutil.move(str(source), str(destination))
        return True
    
    @staticmethod
    def load_json(path: Union[str, Path]) -> Optional[dict]:
        """
        Load JSON file.
        
        Args:
            path: JSON file path
            
        Returns:
            Dictionary or None if error
        """
        content = FileUtils.safe_read(path)
        if content is None:
            return None
        
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None
    
    @staticmethod
    def save_json(path: Union[str, Path], data: dict, indent: int = 2) -> bool:
        """
        Save data to JSON file.
        
        Args:
            path: JSON file path
            data: Data to save
            indent: JSON indentation
            
        Returns:
            True if successful
        """
        try:
            content = json.dumps(data, indent=indent, ensure_ascii=False)
            FileUtils.safe_write(path, content)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_relative_path(path: Union[str, Path], base: Union[str, Path]) -> Path:
        """
        Get relative path from base.
        
        Args:
            path: Target path
            base: Base path
            
        Returns:
            Relative path
        """
        path = Path(path).resolve()
        base = Path(base).resolve()
        
        try:
            return path.relative_to(base)
        except ValueError:
            # Not relative, return absolute path
            return path
    
    @staticmethod
    def normalize_path(path: Union[str, Path]) -> Path:
        """
        Normalize path for cross-platform compatibility.
        
        Args:
            path: Path to normalize
            
        Returns:
            Normalized Path object
        """
        return Path(path).as_posix()