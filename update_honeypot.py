cd ~/honeypot/scripts
cat > update_honeypot.py << 'EOF'
#!/usr/bin/env python3
"""
Script de dynamisme pour Cowrie
Met à jour les fichiers du honeypot de manière réaliste
"""

import os
from datetime import datetime, timedelta
import random

HONEYFS = "/home/cowrie/cowrie/honeyfs"

def add_bash_history_entry(command, user="root"):
    """Ajoute une commande à l'historique bash"""
    history_file = f"{HONEYFS}/root/.bash_history"
    
    # Créer si n'existe pas
    os.makedirs(os.path.dirname(history_file), exist_ok=True)
    
    with open(history_file, "a") as f:
        f.write(command + "\n")
    
    print(f"[+] Ajouté à bash_history: {command}")

def update_exam_marks():
    """Ajoute de nouvelles notes d'examen"""
    marks_file = f"{HONEYFS}/home/p.adjanohoun/exam_marks_Q1_2025.txt"
    
    new_students = [
        ("2024007", "Kofi Mensah", random.randint(65, 95)),
        ("2024008", "Yacine Ba", random.randint(60, 92)),
        ("2024009", "Awa Ndoye", random.randint(70, 98)),
    ]
    
    with open(marks_file, "a") as f:
        f.write("\n--- Updated: " + datetime.now().isoformat() + " ---\n")
        for student_id, name, score in new_students:
            grade = "A" if score >= 85 else "B" if score >= 75 else "C"
            f.write(f"{student_id}    | {name:20} | {score:3} | {grade}\n")
    
    print(f"[+] Mises à jour des notes: {len(new_students)} nouveaux étudiants")

def add_suspicious_commands():
    """Ajoute des commandes "normales" mais révélatrices"""
    commands = [
        "mysql -u admin -p'NewPass2025!' < /opt/backup/export.sql",
        "tar -czf /tmp/archive.tar.gz /var/lib/student_data/",
        "sftp admin@backup-srv.unpn.local",
        "grep -r 'password' /etc/",
        "find /home -name '*.sql' -o -name '*.xlsx'",
        "ls -la /opt/sensitive/",
        "cat /var/log/apache2/access.log | tail -100",
        "systemctl status mysql",
        "sudo systemctl restart postgresql",
    ]
    
    for cmd in random.sample(commands, k=random.randint(2, 4)):
        add_bash_history_entry(cmd)

def main():
    print("[*] Mise à jour du honeypot...")
    print(f"[*] Timestamp: {datetime.now().isoformat()}")
    
    # 1. Ajouter des entrées bash_history réalistes
    add_suspicious_commands()
    
    # 2. Mettre à jour les fichiers d'examen
    # update_exam_marks()  # Décommenter si tu veux changer les notes
    
    print("[✓] Honeypot mis à jour")

if __name__ == "__main__":
    main()
EOF

chmod +x update_honeypot.py
