"""
Password management functionality for FortressGuard
"""

import os
import json
import base64
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class PasswordManager:
    def __init__(self, filename):
        self.filename = filename
        self.password_store = {}
        self.password_history = {}
        self.secure_notes = {}
        self.shared_passwords = {}
        self.password_metrics = {}
        self.load_passwords()

    def generate_key(self):
        return get_random_bytes(16)

    def encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return iv + ct_bytes

    def decrypt(self, encrypted_data, key):
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

    def save_password(self, service, username, password):
        key = self.generate_key()
        encrypted_password = self.encrypt(password, key)
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        if service not in self.password_store:
            self.password_store[service] = {}
        
        self.password_store[service][username] = {
            'password': encoded_password,
            'key': base64.b64encode(key).decode('utf-8'),
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        
        self.save_to_file()
        self.add_to_password_history(service, username, password)
        self.track_password_strength(service, username, password)

    def save_to_file(self):
        data = {
            'passwords': self.password_store,
            'notes': self.secure_notes,
            'history': self.password_history,
            'shared': self.shared_passwords,
            'metrics': self.password_metrics
        }
        
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        with open(self.filename, 'w') as f:
            json.dump(data, f)

    def load_passwords(self):
        if not os.path.exists(self.filename):
            self.save_to_file()
            return
            
        try:
            with open(self.filename, 'r') as f:
                data = json.load(f)
                self.password_store = data.get('passwords', {})
                self.secure_notes = data.get('notes', {})
                self.password_history = data.get('history', {})
                self.shared_passwords = data.get('shared', {})
                self.password_metrics = data.get('metrics', {})
        except json.JSONDecodeError:
            self.password_store = {}
            self.secure_notes = {}
            self.password_history = {}
            self.shared_passwords = {}
            self.password_metrics = {}
            self.save_to_file()

    def retrieve_password(self, service, username):
        if service in self.password_store and username in self.password_store[service]:
            data = self.password_store[service][username]
            encrypted_password = base64.b64decode(data['password'])
            key = base64.b64decode(data['key'])
            return self.decrypt(encrypted_password, key)
        raise ValueError("Password not found")

    def list_passwords(self):
        return {service: list(users.keys()) for service, users in self.password_store.items()}

    def delete_password(self, service, username):
        if service in self.password_store and username in self.password_store[service]:
            del self.password_store[service][username]
            if not self.password_store[service]:
                del self.password_store[service]
            self.save_to_file()
        else:
            raise ValueError("Password not found")

    def delete_passwords(self):
        self.password_store = {}
        self.save_to_file()

    def add_to_password_history(self, service, username, password):
        if service not in self.password_history:
            self.password_history[service] = {}
        if username not in self.password_history[service]:
            self.password_history[service][username] = []
            
        key = self.generate_key()
        encrypted_password = self.encrypt(password, key)
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        self.password_history[service][username].append({
            'password': encoded_password,
            'key': base64.b64encode(key).decode('utf-8'),
            'date': datetime.now().isoformat()
        })
        
        if len(self.password_history[service][username]) > 10:
            self.password_history[service][username].pop(0)
        
        self.save_to_file()

    def get_password_history(self, service, username):
        if service in self.password_history and username in self.password_history[service]:
            history = []
            for entry in self.password_history[service][username]:
                encrypted_password = base64.b64decode(entry['password'])
                key = base64.b64decode(entry['key'])
                decrypted_password = self.decrypt(encrypted_password, key)
                history.append({
                    'password': decrypted_password,
                    'date': entry['date']
                })
            return history
        return []

    def track_password_strength(self, service, username, password):
        if service not in self.password_metrics:
            self.password_metrics[service] = {}
        if username not in self.password_metrics[service]:
            self.password_metrics[service][username] = []
            
        metrics = {
            'length': len(password),
            'uppercase': sum(1 for c in password if c.isupper()),
            'lowercase': sum(1 for c in password if c.islower()),
            'digits': sum(1 for c in password if c.isdigit()),
            'special': sum(1 for c in password if not c.isalnum()),
            'date': datetime.now().isoformat()
        }
        
        self.password_metrics[service][username].append(metrics)
        self.save_to_file()

    def save_secure_note(self, category, title, note_content):
        key = self.generate_key()
        encrypted_note = self.encrypt(note_content, key)
        encoded_note = base64.b64encode(encrypted_note).decode('utf-8')
        
        if category not in self.secure_notes:
            self.secure_notes[category] = {}
            
        self.secure_notes[category][title] = {
            'content': encoded_note,
            'key': base64.b64encode(key).decode('utf-8'),
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }
        self.save_to_file()

    def get_secure_note(self, category, title):
        if category in self.secure_notes and title in self.secure_notes[category]:
            note_data = self.secure_notes[category][title]
            encrypted_note = base64.b64decode(note_data['content'])
            key = base64.b64decode(note_data['key'])
            return self.decrypt(encrypted_note, key)
        raise ValueError("Note not found")

    def share_password(self, service, username, recipient, expiry_hours=24):
        if service in self.password_store and username in self.password_store[service]:
            share_id = os.urandom(16).hex()
            expiry_time = datetime.now().timestamp() + (expiry_hours * 3600)
            
            self.shared_passwords[share_id] = {
                'service': service,
                'username': username,
                'recipient': recipient,
                'expiry': expiry_time,
                'created': datetime.now().isoformat()
            }
            self.save_to_file()
            return share_id
        raise ValueError("Password not found")

    def access_shared_password(self, share_id):
        if share_id in self.shared_passwords:
            share_data = self.shared_passwords[share_id]
            if datetime.now().timestamp() > share_data['expiry']:
                del self.shared_passwords[share_id]
                self.save_to_file()
                raise ValueError("Share link expired")
                
            return self.retrieve_password(share_data['service'], share_data['username'])
        raise ValueError("Share not found") 