import sys
import os
import string
import random
import hashlib
import base64
import json
import logging
import re
import math
import secrets
import hmac
import zlib
import threading
import socket
from datetime import datetime
from pathlib import Path
from io import BytesIO
from PyQt5.QtWidgets import QAbstractScrollArea

# PyQt5 imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QHBoxLayout, QLabel, QPushButton, QLineEdit, 
    QTextEdit, QComboBox, QSpinBox, QCheckBox, 
    QTabWidget, QFileDialog, QMessageBox, QGroupBox,
    QTableWidget, QTableWidgetItem, QScrollArea,
    QProgressBar, QRadioButton, QButtonGroup, QFrame
)
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer

# Cryptography imports
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Image processing
from PIL import Image

# Import the lock icon
try:
    from lock_icon import LOCK_ICON
except ImportError:
    LOCK_ICON = None  # Fallback if icon import fails

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cryptosystem.log')
    ]
)

class CipherMode:
    AES_CBC = "AES-CBC"
    CHACHA20 = "CHACHA20"
    RSA = "RSA"

    @classmethod
    def modes(cls):
        return [cls.AES_CBC, cls.CHACHA20, cls.RSA]

class UsageProfile:
    PERSONAL = "PERSONAL"
    BUSINESS = "BUSINESS"
    MILITARY = "MILITARY"
    DEVELOPER = "DEVELOPER"

class SecurityLevel:
    STANDARD = "STANDARD"
    HIGH = "HIGH"
    PARANOID = "PARANOID"

class NetworkThread(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.running = True
        
    def run(self):
        try:
            # Create a socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(1)
            sock.settimeout(1.0)  # 1 second timeout
            
            while self.running:
                try:
                    conn, addr = sock.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            message = data.decode('utf-8')
                            self.finished.emit(f"Received: {message} from {addr}")
                except socket.timeout:
                    continue
                except Exception as e:
                    self.error.emit(f"Connection error: {str(e)}")
                    
        except Exception as e:
            self.error.emit(f"Network error: {str(e)}")
        finally:
            sock.close()
            
    def stop(self):
        self.running = False

class AdvancedCryptosystem:
    def __init__(self):
        # Load or generate keys for each encryption mode
        self.triple_keys = {
            CipherMode.AES_CBC: self.load_specific_key('aes_cbc_key.bin'),
            CipherMode.CHACHA20: self.load_specific_key('chacha20_key.bin'),
            CipherMode.RSA: self.load_specific_key('rsa_key.bin')
        }
        
        # Generate any missing keys
        if not self.triple_keys[CipherMode.AES_CBC]:
            self.triple_keys[CipherMode.AES_CBC] = get_random_bytes(32)
            self.save_specific_key('aes_cbc_key.bin', self.triple_keys[CipherMode.AES_CBC])
        
        if not self.triple_keys[CipherMode.CHACHA20]:
            self.triple_keys[CipherMode.CHACHA20] = get_random_bytes(32)
            self.save_specific_key('chacha20_key.bin', self.triple_keys[CipherMode.CHACHA20])
        
        if not self.triple_keys[CipherMode.RSA]:
            self.generate_rsa_keys()
            self.save_specific_key('rsa_key.bin', self.triple_keys[CipherMode.RSA])
        
        self.key = self.triple_keys[CipherMode.AES_CBC]  # Default key
        self.password = None
        self.salt = None
        self.iterations = 100000
        self.security_level = SecurityLevel.STANDARD
        self.usage_profile = UsageProfile.PERSONAL
        self.cipher_mode = CipherMode.AES_CBC
        self.network_thread = NetworkThread('localhost', 12345)
        self.network_thread.start()
        self.password_manager = PasswordManager('passwords.json')

    def generate_key(self, size):
        self.key = get_random_bytes(size)
        return self.key

    def change_password(self, password):
        self.password = password
        self.salt = get_random_bytes(16)
        self.iterations = 100000

    def change_encryption_mode(self, mode):
        self.cipher_mode = mode

    def encrypt(self, data):
        if not data:
            raise ValueError("No data provided for encryption")
            
        if self.cipher_mode == CipherMode.AES_CBC:
            if not self.triple_keys[CipherMode.AES_CBC]:
                raise ValueError("AES-CBC key not found")
            cipher = AES.new(self.triple_keys[CipherMode.AES_CBC], AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
            combined = b'CBC:' + cipher.iv + ct_bytes
            return base64.b64encode(combined).decode()
            
        elif self.cipher_mode == CipherMode.CHACHA20:
            if not self.triple_keys[CipherMode.CHACHA20]:
                raise ValueError("ChaCha20 key not found")
            nonce = get_random_bytes(12)
            cipher = ChaCha20.new(key=self.triple_keys[CipherMode.CHACHA20], nonce=nonce)
            ciphertext = cipher.encrypt(data.encode())
            combined = b'CHA:' + nonce + ciphertext
            return base64.b64encode(combined).decode()
            
        elif self.cipher_mode == CipherMode.RSA:
            if not self.triple_keys[CipherMode.RSA]:
                raise ValueError("RSA key not found")
            public_key = RSA.import_key(self.triple_keys[CipherMode.RSA])
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(data.encode())
            combined = b'RSA:' + ciphertext
            return base64.b64encode(combined).decode()

    def decrypt(self, data):
        if not data:
            raise ValueError("No data provided for decryption")

        try:
            # Decode base64
            raw = base64.b64decode(data)
            
            # Extract marker and data
            marker = raw[:4].decode()
            encrypted_data = raw[4:]

            if marker == 'CBC:':
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                cipher = AES.new(self.triple_keys[CipherMode.AES_CBC], AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
                return decrypted.decode()

            elif marker == 'CHA:':
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                cipher = ChaCha20.new(key=self.triple_keys[CipherMode.CHACHA20], nonce=nonce)
                decrypted = cipher.decrypt(ciphertext)
                return decrypted.decode()

            elif marker == 'RSA:':
                private_key = RSA.import_key(self.triple_keys[CipherMode.RSA])
                cipher = PKCS1_OAEP.new(private_key)
                decrypted = cipher.decrypt(encrypted_data)
                return decrypted.decode()

            else:
                raise ValueError(f"Unknown encryption marker: {marker}")

        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def encrypt_file(self, input_path, output_path, progress_callback=None):
        """Encrypt a file using the current cipher mode"""
        try:
            # Read the input file
            with open(input_path, 'rb') as input_file:
                data = input_file.read()
                if progress_callback:
                    progress_callback(0.3)

            # Convert binary data to base64 string for encryption
            b64_data = base64.b64encode(data).decode()
            if progress_callback:
                progress_callback(0.5)

            # Encrypt the data
            encrypted_data = self.encrypt(b64_data)
            if progress_callback:
                progress_callback(0.7)

            # Write the encrypted data
            with open(output_path, 'w') as output_file:
                output_file.write(encrypted_data)
                if progress_callback:
                    progress_callback(1.0)

        except Exception as e:
            logging.error(f"File encryption failed: {str(e)}")
            raise

    def decrypt_file(self, input_path, output_path, progress_callback=None):
        """Decrypt a file using the current cipher mode"""
        try:
            # Read the encrypted file
            with open(input_path, 'r') as input_file:
                encrypted_data = input_file.read()
                if progress_callback:
                    progress_callback(0.3)

            # Decrypt the data
            decrypted_b64 = self.decrypt(encrypted_data)
            if progress_callback:
                progress_callback(0.5)

            # Convert from base64 back to binary
            decrypted_data = base64.b64decode(decrypted_b64)
            if progress_callback:
                progress_callback(0.7)

            # Write the decrypted data
            with open(output_path, 'wb') as output_file:
                output_file.write(decrypted_data)
                if progress_callback:
                    progress_callback(1.0)

        except Exception as e:
            logging.error(f"File decryption failed: {str(e)}")
            raise

    def store_password(self, service, username, password):
        """Store an encrypted password"""
        try:
            self.password_manager.save_password(service, username, password)
            logging.info(f"Stored password for {service} - {username}")
        except Exception as e:
            logging.error(f"Failed to store password: {str(e)}")

    def retrieve_password(self, service, username):
        """Retrieve and decrypt a stored password"""
        return self.password_manager.retrieve_password(service, username)

    def list_passwords(self):
        """List all stored password entries"""
        return self.password_manager.list_passwords()

    def delete_password(self, service, username):
        """Delete a stored password"""
        self.password_manager.delete_password(service, username)

    def analyze_password_strength(self, password, paranoid_mode=False):
        """Analyze password strength using multiple criteria"""
        score = 0
        feedback = []
        recommendations = []

        try:
            # Basic length check with paranoid mode consideration
            length = len(password)
            if paranoid_mode:
                if length >= 20:
                    score += 30
                    feedback.append("Excellent length for paranoid mode")
                elif length >= 16:
                    score += 20
                    feedback.append("Minimum paranoid length met")
                    recommendations.append("Consider using 20+ characters for maximum security in paranoid mode")
                else:
                    score -= 20
                    feedback.append("Too short for paranoid mode")
                    recommendations.append("Paranoid mode requires at least 16 characters")
            else:
                if length >= 16:
                    score += 30
                    feedback.append("Excellent length")
                elif length >= 12:
                    score += 20
                    feedback.append("Good length")
                    recommendations.append("Consider using 16+ characters for maximum security")
                elif length >= 8:
                    score += 10
                    feedback.append("Minimum length met")
                    recommendations.append("Recommended length is 12+ characters")
                else:
                    feedback.append("Password is too short")
                    recommendations.append("Use at least 8 characters, preferably 12+")

            # Character variety checks with paranoid mode consideration
            char_types = 0
            upper = any(c.isupper() for c in password)
            lower = any(c.islower() for c in password)
            digits = any(c.isdigit() for c in password)
            special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)

            if paranoid_mode:
                # In paranoid mode, all character types are required
                if upper:
                    char_types += 1
                    score += 10
                else:
                    score -= 15
                    feedback.append("Missing uppercase letters (required in paranoid mode)")
                    recommendations.append("Add uppercase letters (A-Z)")

                if lower:
                    char_types += 1
                    score += 10
                else:
                    score -= 15
                    feedback.append("Missing lowercase letters (required in paranoid mode)")
                    recommendations.append("Add lowercase letters (a-z)")

                if digits:
                    char_types += 1
                    score += 10
                else:
                    score -= 15
                    feedback.append("Missing numbers (required in paranoid mode)")
                    recommendations.append("Add numbers (0-9)")

                if special:
                    char_types += 1
                    score += 10
                    # Check symbol variety
                    symbol_count = sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?/")
                    if symbol_count < 2:
                        recommendations.append("Paranoid mode: Use multiple special characters")
                else:
                    score -= 15
                    feedback.append("Missing special characters (required in paranoid mode)")
                    recommendations.append("Add special characters (!@#$%^&* etc.)")
            else:
                # Normal mode character checks
                if upper:
                    char_types += 1
                    score += 10
                else:
                    feedback.append("Missing uppercase letters")
                    recommendations.append("Add uppercase letters (A-Z)")

                if lower:
                    char_types += 1
                    score += 10
                else:
                    feedback.append("Missing lowercase letters")
                    recommendations.append("Add lowercase letters (a-z)")

                if digits:
                    char_types += 1
                    score += 10
                else:
                    feedback.append("Missing numbers")
                    recommendations.append("Add numbers (0-9)")

                if special:
                    char_types += 1
                    score += 10
                    # Check symbol variety
                    symbol_count = sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?/")
                    if symbol_count == 1:
                        recommendations.append("Consider using more special characters")
                else:
                    feedback.append("Missing special characters")
                    recommendations.append("Add special characters (!@#$%^&* etc.)")

            # Character distribution bonus
            if char_types >= 4:
                if paranoid_mode and length >= 16:
                    score += 15
                    feedback.append("Excellent character variety for paranoid mode")
                elif length >= 12:
                    score += 10
                    feedback.append("Excellent character mixing")

            # Check for common patterns (stricter in paranoid mode)
            patterns_found = []

            # Repeated characters
            if re.search(r'(.)\1{2,}', password):
                penalty = 25 if paranoid_mode else 15
                score -= penalty
                patterns_found.append("repeated characters")

            # Sequential characters
            if (re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', 
                         password.lower()) or
                re.search(r'(012|123|234|345|456|567|678|789)', password)):
                penalty = 20 if paranoid_mode else 10
                score -= penalty
                patterns_found.append("sequential characters")

            # Keyboard patterns
            keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn']
            if any(pattern in password.lower() for pattern in keyboard_patterns):
                penalty = 25 if paranoid_mode else 15
                score -= penalty
                patterns_found.append("keyboard patterns")

            # Repeated patterns
            if re.search(r'(..+)\1+', password):
                penalty = 25 if paranoid_mode else 15
                score -= penalty
                patterns_found.append("repeated patterns")

            if patterns_found:
                if paranoid_mode:
                    feedback.append(f"Warning: Contains {', '.join(patterns_found)} (critical in paranoid mode)")
                else:
                    feedback.append(f"Contains {', '.join(patterns_found)}")
                recommendations.append("Avoid using common patterns like keyboard sequences or repeated characters")

            # Calculate entropy with higher requirements for paranoid mode
            char_set_size = (26 if upper else 0) + (26 if lower else 0) + \
                           (10 if digits else 0) + (32 if special else 0)
            if char_set_size > 0:
                entropy = length * math.log2(char_set_size)
                if paranoid_mode:
                    if entropy >= 100:
                        score += 15
                        feedback.append("Exceptional entropy for paranoid mode")
                    elif entropy >= 80:
                        score += 10
                        feedback.append("Good entropy for paranoid mode")
                    else:
                        recommendations.append("Increase complexity for better entropy (paranoid mode)")
                else:
                    if entropy >= 80:
                        score += 10
                        feedback.append("High entropy (very strong)")
                    elif entropy >= 60:
                        score += 5
                        feedback.append("Good entropy")
                    else:
                        recommendations.append("Increase password complexity for better entropy")

            # Normalize score
            score = max(0, min(100, score))

            # Determine strength category (stricter in paranoid mode)
            if paranoid_mode:
                if score >= 90:
                    strength = "Paranoid-Ready"
                    color = "#2ecc71"  # Green
                elif score >= 75:
                    strength = "Almost Paranoid"
                    color = "#f1c40f"  # Yellow
                elif score >= 60:
                    strength = "Not Paranoid"
                    color = "#e67e22"  # Orange
                else:
                    strength = "Weak for Paranoid"
                    color = "#e74c3c"  # Red
            else:
                if score >= 80:
                    strength = "Very Strong"
                    color = "#2ecc71"  # Green
                elif score >= 60:
                    strength = "Strong"
                    color = "#f1c40f"  # Yellow
                elif score >= 40:
                    strength = "Moderate"
                    color = "#e67e22"  # Orange
                else:
                    strength = "Weak"
                    color = "#e74c3c"  # Red

            return {
                'score': score,
                'strength': strength,
                'color': color,
                'feedback': feedback,
                'recommendations': recommendations
            }

        except Exception as e:
            logging.error(f"Password analysis failed: {str(e)}")
            return {
                'score': 0,
                'strength': "Error",
                'color': "#e74c3c",
                'feedback': ["Error analyzing password"],
                'recommendations': ["Please try again"]
            }

    def hide_data_in_image(self, image_path, data, output_path):
        """Hide data in an image using LSB steganography"""
        try:
            # Open and verify the image
            if not os.path.exists(image_path):
                raise ValueError("Image file does not exist")
            
            img = Image.open(image_path)
            
            # Convert image to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get image dimensions
            width, height = img.size
            max_bytes = (width * height * 3) // 8  # Each pixel can store 3 bits (RGB)
            
            # Convert data to binary
            binary_data = ''.join(format(ord(i), '08b') for i in data)
            binary_data += '0' * 8  # Add null terminator
            
            # Check if image is large enough
            if len(binary_data) > max_bytes * 8:
                raise ValueError(f"Image too small to hide this data. Maximum size: {max_bytes} bytes")

            # Get pixel data
            pixels = list(img.getdata())
            pixel_count = len(pixels)
            
            # Modify pixels to hide data
            modified_pixels = []
            data_index = 0
            
            for i in range(pixel_count):
                if data_index < len(binary_data):
                    # Get current pixel
                    r, g, b = pixels[i]
                    
                    # Modify R channel
                    if data_index < len(binary_data):
                        r = (r & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    # Modify G channel
                    if data_index < len(binary_data):
                        g = (g & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    # Modify B channel
                    if data_index < len(binary_data):
                        b = (b & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    modified_pixels.append((r, g, b))
                else:
                    modified_pixels.append(pixels[i])
            
            # Create new image with modified pixels
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(modified_pixels)
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            # Save as PNG to prevent data loss
            output_path = os.path.splitext(output_path)[0] + '.png'
            new_img.save(output_path, 'PNG')
            
            # Verify data was hidden correctly
            verification = self.extract_data_from_image(output_path)
            if verification != data:
                raise ValueError("Data verification failed")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to hide data in image: {str(e)}")
            raise

    def extract_data_from_image(self, image_path):
        """Extract hidden data from an image"""
        try:
            # Verify image exists
            if not os.path.exists(image_path):
                raise ValueError("Image file does not exist")
            
            # Open the image
            img = Image.open(image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get pixel data
            pixels = list(img.getdata())
            
            # Extract binary data
            binary_data = ''
            for pixel in pixels:
                r, g, b = pixel
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
            
            # Convert binary to text
            data = ''
            # Process 8 bits at a time
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if byte == '00000000':  # Null terminator found
                    break
                if len(byte) == 8:  # Ensure we have a full byte
                    data += chr(int(byte, 2))
            
            return data
            
        except Exception as e:
            logging.error(f"Failed to extract data from image: {str(e)}")
            raise

    def secure_delete_file(self, file_path, passes=7, progress_callback=None):
        """Securely delete a file by overwriting it multiple times"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError("File not found")
            
            file_size = os.path.getsize(file_path)
            
            for pass_num in range(passes):
                with open(file_path, 'wb') as f:
                    # Different patterns for each pass
                    if pass_num == 0:
                        pattern = b'\x00'  # All zeros
                    elif pass_num == passes - 1:
                        pattern = b'\xFF'  # All ones
                    else:
                        pattern = os.urandom(1)  # Random data
                    
                    # Write in chunks
                    chunk_size = 4096
                    remaining = file_size
                    
                    while remaining > 0:
                        write_size = min(chunk_size, remaining)
                        f.write(pattern * write_size)
                        remaining -= write_size
                        
                        if progress_callback:
                            total_progress = (pass_num + (file_size - remaining) / file_size) / passes
                            progress_callback(total_progress)
                
                # Flush to disk
                os.fsync(f.fileno())
            
            # Finally, delete the file
            os.remove(file_path)
            
        except Exception as e:
            logging.error(f"Failed to securely delete file: {e}")
            raise

    def emergency_destruction(self):
        """Emergency protocol to destroy all sensitive data"""
        try:
            # 1. Destroy encryption keys
            self.key = None
            self.password = None
            self.salt = None
            
            # 2. Clear stored passwords
            self.password_manager.delete_passwords()
            
            # 3. Stop network operations
            if hasattr(self, 'network_thread'):
                self.network_thread.stop()
            
            # 4. Delete configuration files
            config_files = [
                'config.json',
                'cryptosystem.log',
                self.password_manager.filename
            ]
            
            for file in config_files:
                if file and os.path.exists(file):
                    self.secure_delete_file(file)
            
            logging.info("Emergency destruction completed")
            
        except Exception as e:
            logging.error(f"Emergency destruction failed: {e}")
            raise

    def save_stored_passwords(self):
        self.password_manager.save_to_file()

    def generate_rsa_keys(self):
        key = RSA.generate(2048)  # Generate a new RSA key pair
        self.triple_keys[CipherMode.RSA] = key.export_key()  # Store the public key for encryption

    def save_key(self, key):
        with open('key.bin', 'wb') as key_file:
            key_file.write(key)

    def load_key(self):
        if Path('key.bin').exists():
            with open('key.bin', 'rb') as key_file:
                return key_file.read()
        return None

    def debug_keys(self):
        """Debug method to check key status"""
        try:
            for mode, key in self.triple_keys.items():
                if not key:
                    logging.info(f"Key for {mode}: Missing")
        except Exception as e:
            logging.error(f"Error checking keys: {str(e)}")

    def save_specific_key(self, filename, key):
        """Save a specific key to a file"""
        try:
            key_dir = os.path.join(os.path.expanduser('~'), '.cryptosystem', 'keys')
            os.makedirs(key_dir, exist_ok=True)
            key_path = os.path.join(key_dir, filename)
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
        except Exception as e:
            logging.error(f"Failed to save key {filename}: {str(e)}")

    def load_specific_key(self, filename):
        """Load a specific key from a file"""
        try:
            key_dir = os.path.join(os.path.expanduser('~'), '.cryptosystem', 'keys')
            key_path = os.path.join(key_dir, filename)
            if os.path.exists(key_path):
                with open(key_path, 'rb') as key_file:
                    return key_file.read()
        except Exception as e:
            logging.error(f"Failed to load key {filename}: {str(e)}")
        return None

class PasswordManager:
    def __init__(self, filename):
        self.filename = filename
        self.password_store = {}
        self.password_history = {}  # Store password history
        self.secure_notes = {}      # Store encrypted notes
        self.shared_passwords = {}  # Store shared password info
        self.password_metrics = {}  # Store password strength history
        self.load_passwords()
        self.load_secure_notes()
        self.load_password_history()
        self.load_shared_passwords()
        self.load_password_metrics()

    def generate_key(self):
        return get_random_bytes(16)  # AES key size is 16 bytes (128 bits)

    def encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return iv + ct_bytes  # Return IV and ciphertext

    def decrypt(self, encrypted_data, key):
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

    def save_password(self, service, username, password):
        key = self.generate_key()  # Generate a new key for each password
        encrypted_password = self.encrypt(password, key)
        
        # Encode the encrypted password to a base64 string for JSON serialization
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        self.password_store[service] = {username: (encoded_password, base64.b64encode(key).decode('utf-8'))}
        self.save_to_file()

    def save_to_file(self):
        """Save all data to file"""
        data = {
            'passwords': self.password_store,
            'notes': self.secure_notes,
            'history': self.password_history,
            'shared': self.shared_passwords,
            'metrics': self.password_metrics
        }
        with open(self.filename, 'w') as f:
            json.dump(data, f)

    def load_passwords(self):
        """Load all data from file"""
        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as f:
                json.dump({}, f)
        else:
            try:
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    self.password_store = data.get('passwords', {})
                    self.secure_notes = data.get('notes', {})
                    self.password_history = data.get('history', {})
                    self.shared_passwords = data.get('shared', {})
                    self.password_metrics = data.get('metrics', {})
            except json.JSONDecodeError:
                logging.error("Failed to decode JSON, initializing empty stores.")
                self.password_store = {}
                self.secure_notes = {}
                self.password_history = {}
                self.shared_passwords = {}
                self.password_metrics = {}
                self.save_to_file()

    def load_secure_notes(self):
        """Placeholder for backward compatibility"""
        pass

    def load_password_history(self):
        """Placeholder for backward compatibility"""
        pass

    def load_shared_passwords(self):
        """Placeholder for backward compatibility"""
        pass

    def load_password_metrics(self):
        """Placeholder for backward compatibility"""
        pass

    def save_secure_note(self, category, title, note_content):
        """Save an encrypted secure note"""
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
        """Retrieve a secure note"""
        if category in self.secure_notes and title in self.secure_notes[category]:
            note_data = self.secure_notes[category][title]
            encrypted_note = base64.b64decode(note_data['content'])
            key = base64.b64decode(note_data['key'])
            return self.decrypt(encrypted_note, key)
        raise ValueError("Note not found")

    def share_password(self, service, username, recipient, expiry_hours=24):
        """Share a password with temporary access"""
        if service in self.password_store and username in self.password_store[service]:
            share_id = secrets.token_urlsafe(16)
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
        """Access a shared password"""
        if share_id in self.shared_passwords:
            share_data = self.shared_passwords[share_id]
            if datetime.now().timestamp() > share_data['expiry']:
                del self.shared_passwords[share_id]
                self.save_to_file()
                raise ValueError("Share link expired")
                
            return self.retrieve_password(share_data['service'], share_data['username'])
        raise ValueError("Share not found")

    def add_to_password_history(self, service, username, password):
        """Add a password to history"""
        if service not in self.password_history:
            self.password_history[service] = {}
        if username not in self.password_history[service]:
            self.password_history[service][username] = []
            
        # Encrypt the historical password
        key = self.generate_key()
        encrypted_password = self.encrypt(password, key)
        encoded_password = base64.b64encode(encrypted_password).decode('utf-8')
        
        self.password_history[service][username].append({
            'password': encoded_password,
            'key': base64.b64encode(key).decode('utf-8'),
            'date': datetime.now().isoformat()
        })
        
        # Keep only last 10 passwords
        if len(self.password_history[service][username]) > 10:
            self.password_history[service][username].pop(0)
        
        self.save_to_file()

    def get_password_history(self, service, username):
        """Get password history for a service/username"""
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
        """Track password strength metrics over time"""
        if service not in self.password_metrics:
            self.password_metrics[service] = {}
        if username not in self.password_metrics[service]:
            self.password_metrics[service][username] = []
            
        # Calculate metrics
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

    def export_passwords(self, export_path, include_history=False):
        """Export passwords to encrypted file"""
        export_data = {
            'passwords': self.password_store,
            'notes': self.secure_notes,
            'history': self.password_history if include_history else {},
            'metrics': self.password_metrics,
            'export_date': datetime.now().isoformat()
        }
        
        # Generate a new key for the export
        export_key = self.generate_key()
        encrypted_data = self.encrypt(json.dumps(export_data), export_key)
        
        with open(export_path, 'wb') as f:
            f.write(encrypted_data)
            
        return export_key

    def import_passwords(self, import_path, import_key):
        """Import passwords from encrypted file"""
        with open(import_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self.decrypt(encrypted_data, import_key)
        imported_data = json.loads(decrypted_data)
        
        # Merge imported data with existing data
        self.password_store.update(imported_data.get('passwords', {}))
        self.secure_notes.update(imported_data.get('notes', {}))
        self.password_history.update(imported_data.get('history', {}))
        self.password_metrics.update(imported_data.get('metrics', {}))
        
        self.save_to_file()

    def retrieve_password(self, service, username):
        if service in self.password_store and username in self.password_store[service]:
            encrypted_password, key = self.password_store[service][username]
            return self.decrypt(base64.b64decode(encrypted_password), base64.b64decode(key))
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

# Passwords are saved in the following file:
# C:/Users/raijm/Downloads/passwords.json

class PasswordStorageWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Password Entry
        entry_group = QGroupBox("Store New Password")
        entry_layout = QVBoxLayout()

        # Service/Website
        service_layout = QHBoxLayout()
        self.service_label = QLabel("Service/Website:")
        self.service_label.setStyleSheet("color: black;")
        self.service_input = QLineEdit()
        service_layout.addWidget(self.service_label)
        service_layout.addWidget(self.service_input)
        entry_layout.addLayout(service_layout)

        # Username/Email
        username_layout = QHBoxLayout()
        self.username_label = QLabel("Username/Email:")
        self.username_label.setStyleSheet("color: black;")
        self.username_input = QLineEdit()
        username_layout.addWidget(self.username_label)
        username_layout.addWidget(self.username_input)
        entry_layout.addLayout(username_layout)

        # Password
        password_layout = QHBoxLayout()
        self.password_label = QLabel("Password:")
        self.password_label.setStyleSheet("color: black;")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)
        entry_layout.addLayout(password_layout)

        # Store Button
        self.store_btn = QPushButton("Store Password")
        self.store_btn.clicked.connect(self.store_password)
        entry_layout.addWidget(self.store_btn)

        entry_group.setLayout(entry_layout)
        layout.addWidget(entry_group)

        # Password List
        list_group = QGroupBox("Stored Passwords")
        list_layout = QVBoxLayout()

        # Password Table
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(3)
        self.password_table.setHorizontalHeaderLabels(["Service", "Username", "Actions"])
        self.password_table.horizontalHeader().setStretchLastSection(True)
        self.password_table.setStyleSheet("QTableWidget { color: white; background-color: #4A4A4A; }")
        self.password_table.setFixedHeight(300)  # Set a fixed height for the password table
        self.password_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)  # Prevent the table from shrinking
        self.password_table.setFixedHeight(300)  # Set a fixed height for the password table
        self.password_table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)  # Prevent the table from shrinking
        list_layout.addWidget(self.password_table)

        # Refresh and Delete Buttons
        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.refresh_password_list)
        btn_layout.addWidget(self.refresh_btn)
        list_layout.addLayout(btn_layout)

        list_group.setLayout(list_layout)
        layout.addWidget(list_group)

        self.setLayout(layout)
        self.refresh_password_list()

    def store_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not all([service, username, password]):
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")
            return

        try:
            self.cryptosystem.password_manager.save_password(service, username, password)
            logging.info(f"Stored password for {service} - {username}")
            QMessageBox.information(self, "Success", "Password stored successfully!")
            self.service_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            logging.error(f"Failed to save password: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save password: {str(e)}")

    def refresh_password_list(self):
        try:
            passwords = self.cryptosystem.list_passwords()
            self.password_table.setRowCount(0)
            
            for service, usernames in passwords.items():
                for username in usernames:
                    row = self.password_table.rowCount()
                    self.password_table.insertRow(row)
                    
                    # Add service and username
                    self.password_table.setItem(row, 0, QTableWidgetItem(service))
                    self.password_table.setItem(row, 1, QTableWidgetItem(username))
                    
                    # Add action buttons
                    actions_widget = QWidget()
                    actions_layout = QHBoxLayout()
                    actions_layout.setContentsMargins(0, 0, 0, 0)
                    
                    view_btn = QPushButton("View")
                    view_btn.clicked.connect(lambda checked, s=service, u=username: 
                                          self.view_password(s, u))
                    
                    delete_btn = QPushButton("Delete")
                    delete_btn.clicked.connect(lambda checked, s=service, u=username: 
                                            self.delete_password(s, u))
                    
                    actions_layout.addWidget(view_btn)
                    actions_layout.addWidget(delete_btn)
                    actions_widget.setLayout(actions_layout)
                    
                    self.password_table.setCellWidget(row, 2, actions_widget)
            
            self.password_table.resizeColumnsToContents()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to refresh password list: {str(e)}")

    def view_password(self, service, username):
        try:
            password = self.cryptosystem.retrieve_password(service, username)
            msg = QMessageBox(self)
            msg.setStyleSheet("color: black;")  # Set text color to black for the popup
            msg.setWindowTitle("Stored Password")
            msg.setText(f"Service: {service}\nUsername: {username}\nPassword: {password}")
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {str(e)}")

    def delete_password(self, service, username):
        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the password for {username} at {service}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            try:
                self.cryptosystem.delete_password(service, username)
                QMessageBox.information(self, "Success", "Password deleted successfully!")
                self.refresh_password_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete password: {str(e)}")

class EncryptionWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Mode Selection
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Encryption Mode:")
        self.mode_combo = QComboBox()
        for mode in CipherMode.modes():
            self.mode_combo.addItem(mode)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)

        # Text Encryption
        text_group = QGroupBox("Text Encryption/Decryption")
        text_layout = QVBoxLayout()

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter text to encrypt/decrypt")
        text_layout.addWidget(self.input_text)

        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        text_layout.addLayout(button_layout)

        text_group.setLayout(text_layout)
        layout.addWidget(text_group)

        # File Encryption
        file_group = QGroupBox("File Encryption/Decryption")
        file_layout = QVBoxLayout()

        # Input file
        input_file_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_path.setPlaceholderText("Input file path")
        self.input_file_button = QPushButton("Browse")
        self.input_file_button.clicked.connect(self.browse_input_file)
        input_file_layout.addWidget(self.input_file_path)
        input_file_layout.addWidget(self.input_file_button)
        file_layout.addLayout(input_file_layout)

        # Output file
        output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setPlaceholderText("Output file path")
        self.output_file_button = QPushButton("Browse")
        self.output_file_button.clicked.connect(self.browse_output_file)
        output_file_layout.addWidget(self.output_file_path)
        output_file_layout.addWidget(self.output_file_button)
        file_layout.addLayout(output_file_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        file_layout.addWidget(self.progress_bar)

        # File encryption buttons
        file_button_layout = QHBoxLayout()
        self.encrypt_file_button = QPushButton("Encrypt File")
        self.decrypt_file_button = QPushButton("Decrypt File")
        self.encrypt_file_button.clicked.connect(self.encrypt_file)
        self.decrypt_file_button.clicked.connect(self.decrypt_file)
        file_button_layout.addWidget(self.encrypt_file_button)
        file_button_layout.addWidget(self.decrypt_file_button)
        file_layout.addLayout(file_button_layout)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        self.setLayout(layout)

    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if file_path:
            self.input_file_path.setText(file_path)
            # Auto-generate output path
            base, ext = os.path.splitext(file_path)
            if self.encrypt_file_button.isEnabled():
                self.output_file_path.setText(f"{base}_encrypted{ext}")
            else:
                self.output_file_path.setText(f"{base}_decrypted{ext}")

    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if file_path:
            self.output_file_path.setText(file_path)

    def update_progress(self, value):
        self.progress_bar.setValue(int(value * 100))

    def encrypt_file(self):
        try:
            input_path = self.input_file_path.text()
            output_path = self.output_file_path.text()
            
            if not input_path or not output_path:
                QMessageBox.warning(self, "Error", "Please select both input and output files")
                return
                
            if not os.path.exists(input_path):
                QMessageBox.warning(self, "Error", "Input file does not exist")
                return

            # Show progress bar
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            # Set encryption mode
            mode = CipherMode.modes()[self.mode_combo.currentIndex()]
            self.cryptosystem.change_encryption_mode(mode)

            # Encrypt file
            self.cryptosystem.encrypt_file(input_path, output_path, self.update_progress)
            
            QMessageBox.information(self, "Success", "File encrypted successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def decrypt_file(self):
        try:
            input_path = self.input_file_path.text()
            output_path = self.output_file_path.text()
            
            if not input_path or not output_path:
                QMessageBox.warning(self, "Error", "Please select both input and output files")
                return
                
            if not os.path.exists(input_path):
                QMessageBox.warning(self, "Error", "Input file does not exist")
                return

            # Show progress bar
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            # Set encryption mode
            mode = CipherMode.modes()[self.mode_combo.currentIndex()]
            self.cryptosystem.change_encryption_mode(mode)

            # Decrypt file
            self.cryptosystem.decrypt_file(input_path, output_path, self.update_progress)
            
            QMessageBox.information(self, "Success", "File decrypted successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def encrypt_text(self):
        try:
            mode = CipherMode.modes()[self.mode_combo.currentIndex()]
            self.cryptosystem.change_encryption_mode(mode)
            text = self.input_text.toPlainText()
            if not text:
                raise ValueError("Please enter text to encrypt")
            encrypted = self.cryptosystem.encrypt(text)
            self.input_text.setText(encrypted)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        try:
            mode = CipherMode.modes()[self.mode_combo.currentIndex()]
            self.cryptosystem.change_encryption_mode(mode)
            text = self.input_text.toPlainText()
            if not text:
                raise ValueError("Please enter text to decrypt")
            decrypted = self.cryptosystem.decrypt(text)
            self.input_text.setText(decrypted)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

class PasswordGeneratorWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def estimate_crack_time(self, password):
        """Estimate the time needed to crack the password using brute force"""
        try:
            # Define character set sizes
            charset_size = 0
            if any(c.isupper() for c in password):
                charset_size += 26
            if any(c.islower() for c in password):
                charset_size += 26
            if any(c.isdigit() for c in password):
                charset_size += 10
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password):
                charset_size += 32

            # If no characters found, return "Invalid password"
            if charset_size == 0:
                return "Invalid password"

            # Average attempts needed = (charset_size^length) / 2
            possible_combinations = (charset_size ** len(password)) / 2
            
            # Assume 100 billion attempts per second (modern hardware)
            attempts_per_second = 100_000_000_000
            
            # Calculate seconds needed
            seconds = possible_combinations / attempts_per_second
            
            # Convert to appropriate unit
            if seconds < 60:
                return f"~{seconds:.1f} seconds"
            elif seconds < 3600:
                minutes = seconds / 60
                return f"~{minutes:.1f} minutes"
            elif seconds < 86400:
                hours = seconds / 3600
                return f"~{hours:.1f} hours"
            elif seconds < 31536000:
                days = seconds / 86400
                return f"~{days:.1f} days"
            else:
                years = seconds / 31536000
                if years < 1000000:
                    return f"~{years:.1f} years"
                elif years < 1000000000:
                    return f"~{years/1000:.1f} thousand years"
                elif years < 1000000000000:
                    return f"~{years/1000000:.1f} million years"
                else:
                    return f"~{years/1000000000:.1f} billion years"
        except Exception as e:
            logging.error(f"Error calculating crack time: {str(e)}")
            return "Error calculating time"

    def init_ui(self):
        layout = QVBoxLayout()

        # Password Generation Options
        options_group = QGroupBox("Password Options")
        options_layout = QVBoxLayout()

        # Length selection
        length_layout = QHBoxLayout()
        self.length_label = QLabel("Password Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.valueChanged.connect(self.on_length_changed)
        length_layout.addWidget(self.length_label)
        length_layout.addWidget(self.length_spin)
        options_layout.addLayout(length_layout)

        # Character sets
        self.use_upper = QCheckBox("Uppercase Letters (A-Z)")
        self.use_lower = QCheckBox("Lowercase Letters (a-z)")
        self.use_digits = QCheckBox("Digits (0-9)")
        self.use_special = QCheckBox("Special Characters (!@#$%^&*())")
        
        # Set defaults and connect signals
        self.use_upper.setChecked(True)
        self.use_lower.setChecked(True)
        self.use_digits.setChecked(True)
        self.use_special.setChecked(True)

        # Connect character set changes to update function
        self.use_upper.stateChanged.connect(self.on_options_changed)
        self.use_lower.stateChanged.connect(self.on_options_changed)
        self.use_digits.stateChanged.connect(self.on_options_changed)
        self.use_special.stateChanged.connect(self.on_options_changed)

        options_layout.addWidget(self.use_upper)
        options_layout.addWidget(self.use_lower)
        options_layout.addWidget(self.use_digits)
        options_layout.addWidget(self.use_special)

        # Paranoid mode with detailed explanation
        paranoid_group = QGroupBox("Security Level")
        paranoid_layout = QVBoxLayout()
        
        self.paranoid_mode = QCheckBox("Paranoid Mode (Maximum Security)")
        self.paranoid_mode.stateChanged.connect(self.on_paranoid_mode_changed)
        paranoid_layout.addWidget(self.paranoid_mode)
        
        paranoid_info = QLabel(
            "Paranoid Mode enforces strict security requirements:\n"
            "• Minimum 16 characters\n"
            "• Must include uppercase, lowercase, numbers, and symbols\n"
            "• No common words or patterns\n"
            "• Enhanced entropy checks\n"
            "• Protection against dictionary attacks\n"
            "• Regular password rotation recommendations\n"
            "\nRecommended for high-security applications like:\n"
            "• Financial accounts\n"
            "• Critical infrastructure\n"
            "• Sensitive data storage"
        )
        paranoid_info.setStyleSheet("color: #666666; font-size: 10pt;")
        paranoid_info.setWordWrap(True)
        paranoid_layout.addWidget(paranoid_info)
        
        paranoid_group.setLayout(paranoid_layout)
        options_layout.addWidget(paranoid_group)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Generated Password
        password_group = QGroupBox("Generated Password")
        password_layout = QVBoxLayout()

        # Password display/edit with real-time update
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Generated password will appear here")
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.textChanged.connect(self.on_password_changed)
        password_layout.addWidget(self.password_edit)

        # Show/Hide password
        show_layout = QHBoxLayout()
        self.show_password = QCheckBox("Show Password")
        self.show_password.stateChanged.connect(self.toggle_password_visibility)
        show_layout.addWidget(self.show_password)
        
        # Copy button
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self.copy_password)
        show_layout.addWidget(self.copy_btn)
        
        password_layout.addLayout(show_layout)

        # Generate button
        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_password)
        password_layout.addWidget(self.generate_btn)

        # Password strength meter
        strength_layout = QHBoxLayout()
        strength_layout.addWidget(QLabel("Password Strength:"))
        self.strength_bar = QProgressBar()
        self.strength_bar.setTextVisible(True)
        strength_layout.addWidget(self.strength_bar)
        password_layout.addLayout(strength_layout)

        # Add crack time estimation
        crack_time_layout = QHBoxLayout()
        crack_time_layout.addWidget(QLabel("Estimated Crack Time:"))
        self.crack_time_label = QLabel("Generate a password to see estimate")
        self.crack_time_label.setStyleSheet("color: #666666;")
        crack_time_layout.addWidget(self.crack_time_label)
        password_layout.addLayout(crack_time_layout)

        # Password feedback
        self.feedback_label = QLabel("")
        self.feedback_label.setWordWrap(True)
        password_layout.addWidget(self.feedback_label)

        password_group.setLayout(password_layout)
        layout.addWidget(password_group)

        # Password Storage
        storage_group = QGroupBox("Password Storage")
        storage_layout = QVBoxLayout()

        # Service and username
        self.service_edit = QLineEdit()
        self.service_edit.setPlaceholderText("Service name (e.g., 'Gmail')")
        storage_layout.addWidget(self.service_edit)

        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username or email")
        storage_layout.addWidget(self.username_edit)

        # Store button
        self.store_btn = QPushButton("Store Password")
        self.store_btn.clicked.connect(self.store_password)
        storage_layout.addWidget(self.store_btn)

        storage_group.setLayout(storage_layout)
        layout.addWidget(storage_group)

        self.setLayout(layout)

    def on_password_changed(self, text):
        """Handle real-time password changes"""
        self.check_password_strength()
        self.update_paranoid_requirements()
        # Update crack time estimate
        if text:
            crack_time = self.estimate_crack_time(text)
            self.crack_time_label.setText(crack_time)
            # Set color based on time
            if "billion years" in crack_time or "million years" in crack_time:
                self.crack_time_label.setStyleSheet("color: #2ecc71;")  # Green
            elif "thousand years" in crack_time or "years" in crack_time:
                self.crack_time_label.setStyleSheet("color: #f1c40f;")  # Yellow
            elif "days" in crack_time:
                self.crack_time_label.setStyleSheet("color: #e67e22;")  # Orange
            else:
                self.crack_time_label.setStyleSheet("color: #e74c3c;")  # Red
        else:
            self.crack_time_label.setText("Generate a password to see estimate")
            self.crack_time_label.setStyleSheet("color: #666666;")

    def on_length_changed(self, value):
        """Handle length spinbox changes"""
        if self.password_edit.text():
            self.check_password_strength()

    def on_options_changed(self):
        """Handle character set option changes"""
        if self.password_edit.text():
            self.check_password_strength()

    def on_paranoid_mode_changed(self, state):
        """Handle paranoid mode changes"""
        if state:
            self.length_spin.setMinimum(16)
            if self.length_spin.value() < 16:
                self.length_spin.setValue(16)
            # Force enable all character sets
            self.use_upper.setChecked(True)
            self.use_lower.setChecked(True)
            self.use_digits.setChecked(True)
            self.use_special.setChecked(True)
        else:
            self.length_spin.setMinimum(8)
        
        if self.password_edit.text():
            self.check_password_strength()

    def update_paranoid_requirements(self):
        """Update UI based on paranoid mode requirements"""
        if self.paranoid_mode.isChecked():
            password = self.password_edit.text()
            if password:
                meets_requirements = (
                    len(password) >= 16 and
                    any(c.isupper() for c in password) and
                    any(c.islower() for c in password) and
                    any(c.isdigit() for c in password) and
                    any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password)
                )
                self.store_btn.setEnabled(meets_requirements)
            else:
                self.store_btn.setEnabled(False)
        else:
            self.store_btn.setEnabled(True)

    def toggle_password_visibility(self, state):
        self.password_edit.setEchoMode(
            QLineEdit.Normal if state else QLineEdit.Password
        )

    def generate_password(self):
        try:
            length = self.length_spin.value()
            chars = ""
            
            # Build character set
            if self.use_upper.isChecked():
                chars += string.ascii_uppercase
            if self.use_lower.isChecked():
                chars += string.ascii_lowercase
            if self.use_digits.isChecked():
                chars += string.digits
            if self.use_special.isChecked():
                chars += "!@#$%^&*"

            if not chars:
                raise ValueError("Please select at least one character set")

            # Generate password
            password = ''.join(secrets.choice(chars) for _ in range(length))

            # Ensure password meets minimum requirements in paranoid mode
            if self.paranoid_mode.isChecked():
                while not (any(c.isupper() for c in password) and
                         any(c.islower() for c in password) and
                         any(c.isdigit() for c in password) and
                         any(c in "!@#$%^&*" for c in password)):
                    password = ''.join(secrets.choice(chars) for _ in range(length))

            self.password_edit.setText(password)
            self.check_password_strength()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def check_password_strength(self):
        """Update UI with password strength analysis"""
        password = self.password_edit.text()
        if not password:
            self.strength_bar.setValue(0)
            self.strength_bar.setFormat("No Password")
            self.strength_bar.setStyleSheet("")
            self.feedback_label.setText("")
            return

        # Get strength analysis with paranoid mode status
        analysis = self.cryptosystem.analyze_password_strength(
            password, 
            paranoid_mode=self.paranoid_mode.isChecked()
        )
        
        # Update strength bar
        self.strength_bar.setValue(analysis['score'])
        self.strength_bar.setFormat(f"{analysis['strength']} ({analysis['score']}%)")
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {analysis['color']}; }}")

        # Build feedback text
        feedback_text = ""
        
        if analysis['feedback']:
            feedback_text += "Current Status:\n"
            feedback_text += "\n".join(f"• {msg}" for msg in analysis['feedback'])
        
        if analysis['recommendations']:
            if feedback_text:
                feedback_text += "\n\n"
            feedback_text += "Recommendations:\n"
            feedback_text += "\n".join(f"• {msg}" for msg in analysis['recommendations'])

        if not analysis['feedback'] and not analysis['recommendations']:
            feedback_text = "Password meets all security criteria!"
            self.feedback_label.setStyleSheet(f"color: {analysis['color']};")
        else:
            self.feedback_label.setStyleSheet("color: #666666;")  # Dark gray

        self.feedback_label.setText(feedback_text)

    def copy_password(self):
        if self.password_edit.text():
            QApplication.clipboard().setText(self.password_edit.text())
            QMessageBox.information(self, "Success", "Password copied to clipboard!")
        else:
            QMessageBox.warning(self, "Warning", "No password to copy!")

    def store_password(self):
        try:
            service = self.service_edit.text()
            username = self.username_edit.text()
            password = self.password_edit.text()

            if not all([service, username, password]):
                raise ValueError("Please fill in all fields")

            self.cryptosystem.store_password(service, username, password)
            QMessageBox.information(self, "Success", "Password stored successfully!")

            # Clear fields
            self.service_edit.clear()
            self.username_edit.clear()
            self.password_edit.clear()
            self.show_password.setChecked(False)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

class StealthOperationsWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Steganography Group
        steg_group = QGroupBox("Steganography")
        steg_layout = QVBoxLayout()

        # Image selection
        image_layout = QHBoxLayout()
        self.image_path = QLineEdit()
        self.image_path.setPlaceholderText("Select image file...")
        self.browse_image = QPushButton("Browse")
        self.browse_image.clicked.connect(self.select_image)
        image_layout.addWidget(self.image_path)
        image_layout.addWidget(self.browse_image)
        steg_layout.addLayout(image_layout)

        # Data input
        self.data_input = QTextEdit()
        self.data_input.setPlaceholderText("Enter data to hide...")
        steg_layout.addWidget(self.data_input)

        # Output image path
        output_layout = QHBoxLayout()
        self.output_path = QLineEdit()
        self.output_path.setPlaceholderText("Output image path...")
        self.browse_output = QPushButton("Browse")
        self.browse_output.clicked.connect(self.select_output)
        output_layout.addWidget(self.output_path)
        output_layout.addWidget(self.browse_output)
        steg_layout.addLayout(output_layout)

        # Operation buttons
        btn_layout = QHBoxLayout()
        self.hide_btn = QPushButton("Hide Data")
        self.extract_btn = QPushButton("Extract Data")
        self.hide_btn.clicked.connect(self.hide_data)
        self.extract_btn.clicked.connect(self.extract_data)
        btn_layout.addWidget(self.hide_btn)
        btn_layout.addWidget(self.extract_btn)
        steg_layout.addLayout(btn_layout)

        # Status label
        self.status_label = QLabel("")
        steg_layout.addWidget(self.status_label)

        steg_group.setLayout(steg_layout)
        layout.addWidget(steg_group)

        # Secure Deletion Group
        del_group = QGroupBox("Secure File Deletion")
        del_layout = QVBoxLayout()

        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select file to securely delete...")
        self.browse_file = QPushButton("Browse")
        self.browse_file.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(self.browse_file)
        del_layout.addLayout(file_layout)

        # Pass count selection
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Number of passes:"))
        self.pass_count = QSpinBox()
        self.pass_count.setRange(1, 35)
        self.pass_count.setValue(7)
        pass_layout.addWidget(self.pass_count)
        del_layout.addLayout(pass_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        del_layout.addWidget(self.progress_bar)

        # Delete button
        self.delete_btn = QPushButton("Securely Delete File")
        self.delete_btn.clicked.connect(self.secure_delete)
        del_layout.addWidget(self.delete_btn)

        del_group.setLayout(del_layout)
        layout.addWidget(del_group)

        # Emergency Destruction
        emerg_group = QGroupBox("Emergency Protocol")
        emerg_layout = QVBoxLayout()

        warning_label = QLabel("Warning: This will permanently destroy all sensitive data!")
        warning_label.setStyleSheet("color: red; font-weight: bold;")
        emerg_layout.addWidget(warning_label)

        self.emergency_btn = QPushButton("Activate Emergency Protocol")
        self.emergency_btn.setStyleSheet("background-color: #ff4444; color: white; font-weight: bold;")
        self.emergency_btn.clicked.connect(self.emergency_protocol)
        emerg_layout.addWidget(self.emergency_btn)

        emerg_group.setLayout(emerg_layout)
        layout.addWidget(emerg_group)

        self.setLayout(layout)

    def select_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp)")
        if file_path:
            self.image_path.setText(file_path)
            # Auto-generate output path
            base = os.path.splitext(file_path)[0]
            self.output_path.setText(f"{base}_hidden.png")

    def select_output(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Image", "", "PNG Files (*.png)")
        if file_path:
            self.output_path.setText(file_path)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Delete")
        if file_path:
            self.file_path.setText(file_path)

    def update_progress(self, value):
        self.progress_bar.setValue(int(value * 100))

    def hide_data(self):
        try:
            image_path = self.image_path.text()
            output_path = self.output_path.text()
            data = self.data_input.toPlainText()

            if not image_path or not output_path:
                raise ValueError("Please select both input and output image paths")
            if not data:
                raise ValueError("Please enter data to hide")

            # Calculate maximum data size
            img = Image.open(image_path)
            
            # Convert image to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get image dimensions
            width, height = img.size
            max_bytes = (width * height * 3) // 8  # Each pixel can store 3 bits (RGB)
            
            # Convert data to binary
            binary_data = ''.join(format(ord(i), '08b') for i in data)
            binary_data += '0' * 8  # Add null terminator
            
            # Check if image is large enough
            if len(binary_data) > max_bytes * 8:
                raise ValueError(f"Image too small to hide this data. Maximum size: {max_bytes} bytes")

            self.cryptosystem.hide_data_in_image(image_path, data, output_path)
            self.status_label.setText("Data hidden successfully!")
            self.status_label.setStyleSheet("color: green;")

        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
            self.status_label.setStyleSheet("color: red;")

    def extract_data(self):
        try:
            image_path = self.image_path.text()
            if not image_path:
                raise ValueError("Please select an image")

            data = self.cryptosystem.extract_data_from_image(image_path)
            self.data_input.setText(data)
            self.status_label.setText("Data extracted successfully!")
            self.status_label.setStyleSheet("color: green;")

        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
            self.status_label.setStyleSheet("color: red;")

    def secure_delete(self):
        try:
            file_path = self.file_path.text()
            if not file_path:
                raise ValueError("Please select a file to delete")

            # Confirm deletion
            reply = QMessageBox.question(
                self, 'Confirm Deletion',
                f"Are you sure you want to securely delete {file_path}?\n"
                "This operation cannot be undone!",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                self.progress_bar.setVisible(True)
                self.progress_bar.setValue(0)
                self.cryptosystem.secure_delete_file(file_path, self.pass_count.value(), self.update_progress)
                QMessageBox.information(self, "Success", "File securely deleted")
                self.file_path.clear()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Secure deletion failed: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)

    def emergency_protocol(self):
        try:
            # Double confirm
            reply = QMessageBox.warning(self, 'Emergency Protocol',
                                      "WARNING: This will permanently destroy all sensitive data!\n"
                                      "This action cannot be undone!\n\n"
                                      "Are you absolutely sure?",
                                      QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                self.cryptosystem.emergency_destruction()
                QMessageBox.information(self, "Success", "Emergency protocol completed")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Emergency protocol failed: {str(e)}")

class SecuritySettingsWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Key Management
        key_group = QGroupBox("Key Management")
        key_layout = QVBoxLayout()

        # Key Generation
        gen_layout = QHBoxLayout()
        self.key_size_label = QLabel("Key Size:")
        self.key_size_spin = QSpinBox()
        self.key_size_spin.setRange(128, 4096)
        self.key_size_spin.setValue(2048)
        gen_layout.addWidget(self.key_size_label)
        gen_layout.addWidget(self.key_size_spin)
        key_layout.addLayout(gen_layout)

        # Generate Button
        self.generate_key_btn = QPushButton("Generate Key")
        self.generate_key_btn.clicked.connect(self.generate_key)
        key_layout.addWidget(self.generate_key_btn)

        key_group.setLayout(key_layout)
        layout.addWidget(key_group)

        # Password Management
        password_group = QGroupBox("Password Management")
        password_layout = QVBoxLayout()

        # Password Input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.password_input)

        # Change Button
        self.change_password_btn = QPushButton("Change Password")
        self.change_password_btn.clicked.connect(self.change_password)
        password_layout.addWidget(self.change_password_btn)

        password_group.setLayout(password_layout)
        layout.addWidget(password_group)

        self.setLayout(layout)

    def generate_key(self):
        try:
            size = self.key_size_spin.value()
            self.cryptosystem.generate_key(size)
            QMessageBox.information(self, "Success", "Key generated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation failed: {str(e)}")

    def change_password(self):
        try:
            password = self.password_input.text()
            if not password:
                raise ValueError("Please enter a new password")
            self.cryptosystem.change_password(password)
            QMessageBox.information(self, "Success", "Password changed successfully!")
            self.password_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Password change failed: {str(e)}")

class InfoWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Create scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        # Container widget for scroll area
        container = QWidget()
        container_layout = QVBoxLayout()

        # Comprehensive Guide
        guide_text = QLabel("""
        <h2 style='color: #00ff00;'>Advanced Cryptosystem Overview</h2>
        <p>This application provides a comprehensive solution for secure data handling, including encryption, password management, and key management.</p>

        <h3 style='color: #00ff00;'>1. Key Management</h3>
        <p>Key management is crucial for maintaining the security of cryptographic systems. Our application implements robust key generation, storage, and rotation mechanisms:</p>
        <ul>
            <li><b style='color: #00ff00;'>Key Generation:</b> Utilizes cryptographically secure random number generators and supports various algorithms, ensuring that keys are unpredictable and resistant to brute-force attacks.</li>
            <li><b style='color: #00ff00;'>Key Storage:</b> Keys are stored securely using AES encryption, ensuring they are never in plaintext. The application employs secure storage practices, including encryption at rest and access controls.</li>
            <li><b style='color: #00ff00;'>Key Rotation:</b> Automatic and manual key rotation options to minimize the risk of key compromise.</li>
        </ul>

        <h3 style='color: #00ff00;'>2. Encryption Methods</h3>
        <p>The application supports multiple encryption algorithms:</p>
        <ul>
            <li><b style='color: #00ff00;'>AES-CBC (Advanced Encryption Standard - Cipher Block Chaining):</b>
                <ul>
                    <li>Industry-standard symmetric encryption</li>
                    <li>Uses 256-bit keys for maximum security</li>
                    <li>CBC mode provides additional security through initialization vectors (IV)</li>
                    <li>Best for: Large files, general data encryption</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>ChaCha20:</b>
                <ul>
                    <li>Modern stream cipher designed for high-speed encryption</li>
                    <li>Particularly efficient on mobile and low-power devices</li>
                    <li>Uses 256-bit keys and 96-bit nonces</li>
                    <li>Best for: Real-time encryption, mobile applications</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>RSA (Rivest-Shamir-Adleman):</b>
                <ul>
                    <li>Public-key cryptography for secure data exchange</li>
                    <li>Uses 2048-bit keys for strong security</li>
                    <li>Allows secure communication without pre-shared keys</li>
                    <li>Best for: Key exchange, digital signatures</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>3. Password Management</h3>
        <p>Our password manager provides comprehensive password security:</p>
        <ul>
            <li><b style='color: #00ff00;'>Password Generation:</b>
                <ul>
                    <li>Customizable length and character sets</li>
                    <li>Options for uppercase, lowercase, numbers, and special characters</li>
                    <li>Real-time strength analysis</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Secure Storage:</b>
                <ul>
                    <li>Each password encrypted with a unique key</li>
                    <li>Zero-knowledge architecture</li>
                    <li>Encrypted backup and restore capabilities</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Password Analysis:</b>
                <ul>
                    <li>Checks for common patterns and weaknesses</li>
                    <li>Entropy calculation</li>
                    <li>Dictionary attack resistance verification</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>4. Secure Notes</h3>
        <p>The secure notes feature provides encrypted storage for sensitive text information:</p>
        <ul>
            <li><b style='color: #00ff00;'>Organization:</b>
                <ul>
                    <li>Category-based organization system</li>
                    <li>Custom categories for flexible organization</li>
                    <li>Title and content structure for easy reference</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Security Features:</b>
                <ul>
                    <li>AES-256 encryption for each note</li>
                    <li>Unique encryption key per note</li>
                    <li>Secure deletion capabilities</li>
                    <li>Automatic locking after inactivity</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Use Cases:</b>
                <ul>
                    <li>Storing sensitive personal information</li>
                    <li>Keeping secure documentation</li>
                    <li>Managing confidential business notes</li>
                    <li>Recording recovery codes and backup information</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Features:</b>
                <ul>
                    <li>Rich text support</li>
                    <li>Search functionality</li>
                    <li>Version history tracking</li>
                    <li>Secure sharing options</li>
                    <li>Export and backup capabilities</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>5. Stealth Operations</h3>
        <p>Advanced features for secure data handling:</p>
        <ul>
            <li><b style='color: #00ff00;'>Secure File Deletion:</b>
                <ul>
                    <li>Multiple overwrite passes (configurable)</li>
                    <li>Implements DoD 5220.22-M standard</li>
                    <li>Verification after deletion</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Steganography:</b>
                <ul>
                    <li>Hide encrypted data within images</li>
                    <li>Supports PNG, JPG, and BMP formats</li>
                    <li>Uses LSB (Least Significant Bit) technique</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Emergency Protocol:</b>
                <ul>
                    <li>Immediate secure deletion of all sensitive data</li>
                    <li>Key revocation</li>
                    <li>Network connection termination</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>6. File Operations</h3>
        <p>Comprehensive file handling capabilities:</p>
        <ul>
            <li><b style='color: #00ff00;'>File Encryption:</b>
                <ul>
                    <li>Supports any file type</li>
                    <li>Progress monitoring</li>
                    <li>Integrity verification</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>File Decryption:</b>
                <ul>
                    <li>Automatic format detection</li>
                    <li>Integrity checking</li>
                    <li>Error recovery capabilities</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>7. Security Features</h3>
        <p>Additional security measures:</p>
        <ul>
            <li><b style='color: #00ff00;'>Logging and Auditing:</b>
                <ul>
                    <li>Detailed activity logs</li>
                    <li>Secure log storage</li>
                    <li>Audit trail for security events</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Memory Protection:</b>
                <ul>
                    <li>Secure memory wiping</li>
                    <li>Protection against memory dumps</li>
                    <li>Key isolation</li>
                </ul>
            </li>
            <li><b style='color: #00ff00;'>Error Handling:</b>
                <ul>
                    <li>Graceful error recovery</li>
                    <li>Detailed error reporting</li>
                    <li>Fail-safe operations</li>
                </ul>
            </li>
        </ul>

        <h3 style='color: #00ff00;'>Best Practices</h3>
        <p>Recommended usage guidelines:</p>
        <ul>
            <li>Regularly rotate encryption keys</li>
            <li>Use strong passwords (minimum 12 characters)</li>
            <li>Enable secure deletion for sensitive files</li>
            <li>Keep regular encrypted backups</li>
            <li>Monitor the audit logs</li>
            <li>Test the emergency protocol periodically</li>
            <li>Categorize secure notes effectively</li>
            <li>Regularly review and update stored information</li>
        </ul>

        <h3 style='color: #00ff00;'>Technical Specifications</h3>
        <ul>
            <li>AES-CBC: 256-bit keys</li>
            <li>ChaCha20: 256-bit keys, 96-bit nonces</li>
            <li>RSA: 2048-bit keys</li>
            <li>Secure deletion: Up to 35 passes</li>
            <li>Password storage: Individual AES-256 encryption</li>
            <li>Steganography: Up to 1/8 of image size capacity</li>
            <li>Secure notes: AES-256 encryption with unique keys</li>
        </ul>

        <h3 style='color: #00ff00;'>Conclusion</h3>
        <p>This application is designed to provide robust security features while maintaining user-friendliness. Regular updates and security audits ensure the highest level of protection for your sensitive data.</p>
        """)
        guide_text.setTextFormat(Qt.RichText)
        guide_text.setWordWrap(True)
        container_layout.addWidget(guide_text)
        
        # Set container layout
        container.setLayout(container_layout)
        
        # Set scroll area widget
        scroll.setWidget(container)
        
        layout.addWidget(scroll)
        
        self.setLayout(layout)

class KeyManagementWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Key Generation Section
        gen_group = QGroupBox("Key Generation")
        gen_layout = QVBoxLayout()
        
        # Key type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Key Type:"))
        self.key_type = QComboBox()
        self.key_type.addItems(["AES-256", "ChaCha20", "RSA-2048", "RSA-4096", "Ed25519"])
        type_layout.addWidget(self.key_type)
        gen_layout.addLayout(type_layout)
        
        # Key options
        self.use_hardware_rng = QCheckBox("Use Hardware RNG (if available)")
        self.use_hardware_rng.setChecked(True)
        gen_layout.addWidget(self.use_hardware_rng)
        
        self.extra_entropy = QCheckBox("Add System Entropy")
        self.extra_entropy.setChecked(True)
        gen_layout.addWidget(self.extra_entropy)
        
        # Generate button
        gen_btn = QPushButton("Generate New Key")
        gen_btn.clicked.connect(self.generate_key)
        gen_layout.addWidget(gen_btn)
        
        gen_group.setLayout(gen_layout)
        layout.addWidget(gen_group)
        
        # Key Storage Section
        storage_group = QGroupBox("Key Storage")
        storage_layout = QVBoxLayout()
        
        # Key list
        self.key_list = QTableWidget()
        self.key_list.setColumnCount(4)
        self.key_list.setHorizontalHeaderLabels(["Key ID", "Type", "Created", "Status"])
        self.key_list.horizontalHeader().setStretchLastSection(True)
        storage_layout.addWidget(self.key_list)
        
        # Key actions
        action_layout = QHBoxLayout()
        export_btn = QPushButton("Export Key")
        export_btn.clicked.connect(self.export_key)
        import_btn = QPushButton("Import Key")
        import_btn.clicked.connect(self.import_key)
        backup_btn = QPushButton("Backup Keys")
        backup_btn.clicked.connect(self.backup_keys)
        action_layout.addWidget(export_btn)
        action_layout.addWidget(import_btn)
        action_layout.addWidget(backup_btn)
        storage_layout.addLayout(action_layout)
        
        storage_group.setLayout(storage_layout)
        layout.addWidget(storage_group)
        
        # Key Rotation Section
        rotation_group = QGroupBox("Key Rotation")
        rotation_layout = QVBoxLayout()
        
        # Rotation settings
        period_layout = QHBoxLayout()
        period_layout.addWidget(QLabel("Rotation Period:"))
        self.rotation_period = QSpinBox()
        self.rotation_period.setRange(1, 365)
        self.rotation_period.setValue(90)
        period_layout.addWidget(self.rotation_period)
        period_layout.addWidget(QLabel("days"))
        rotation_layout.addLayout(period_layout)
        
        self.auto_rotate = QCheckBox("Enable Automatic Rotation")
        rotation_layout.addWidget(self.auto_rotate)
        
        rotate_btn = QPushButton("Rotate Selected Key")
        rotate_btn.clicked.connect(self.rotate_key)
        rotation_layout.addWidget(rotate_btn)
        
        rotation_group.setLayout(rotation_layout)
        layout.addWidget(rotation_group)
        
        # Emergency Section
        emergency_group = QGroupBox("Emergency Actions")
        emergency_layout = QVBoxLayout()
        
        revoke_btn = QPushButton("Revoke Key")
        revoke_btn.clicked.connect(self.revoke_key)
        emergency_layout.addWidget(revoke_btn)
        
        destroy_btn = QPushButton("Secure Destroy")
        destroy_btn.clicked.connect(self.destroy_key)
        destroy_btn.setStyleSheet("background-color: #d63031; color: white;")
        emergency_layout.addWidget(destroy_btn)
        
        emergency_group.setLayout(emergency_layout)
        layout.addWidget(emergency_group)
        
        self.setLayout(layout)
        
        # Initialize key list
        self.refresh_key_list()

    def generate_key(self):
        key_type = self.key_type.currentText()
        try:
            # Add key generation logic here
            QMessageBox.information(self, "Success", f"Generated new {key_type} key")
            self.refresh_key_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate key: {str(e)}")

    def export_key(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(self, "Export Key", "", "Key Files (*.key);;All Files (*)")
            if file_path:
                # Add key export logic here
                QMessageBox.information(self, "Success", "Key exported successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export key: {str(e)}")

    def import_key(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Import Key", "", "Key Files (*.key);;All Files (*)")
            if file_path:
                # Add key import logic here
                QMessageBox.information(self, "Success", "Key imported successfully")
                self.refresh_key_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import key: {str(e)}")

    def backup_keys(self):
        try:
            dir_path = QFileDialog.getExistingDirectory(self, "Select Backup Directory")
            if dir_path:
                # Add key backup logic here
                QMessageBox.information(self, "Success", "Keys backed up successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to backup keys: {str(e)}")

    def rotate_key(self):
        try:
            # Add key rotation logic here
            QMessageBox.information(self, "Success", "Key rotated successfully")
            self.refresh_key_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to rotate key: {str(e)}")

    def revoke_key(self):
        reply = QMessageBox.question(
            self, 'Confirm Revocation',
            "Are you sure you want to revoke this key? This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                # Add key revocation logic here
                QMessageBox.information(self, "Success", "Key revoked successfully")
                self.refresh_key_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to revoke key: {str(e)}")

    def destroy_key(self):
        reply = QMessageBox.warning(
            self, 'Confirm Destruction',
            "WARNING: This will securely destroy the key. This action CANNOT be undone!\n\n"
            "Are you absolutely sure?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                # Add secure key destruction logic here
                QMessageBox.information(self, "Success", "Key destroyed successfully")
                self.refresh_key_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to destroy key: {str(e)}")

    def refresh_key_list(self):
        # Add code to refresh the key list table
        self.key_list.setRowCount(0)  # Clear existing items
        # Add dummy data for demonstration
        dummy_data = [
            ("key_001", "AES-256", "2025-01-09", "Active"),
            ("key_002", "ChaCha20", "2025-01-08", "Active"),
            ("key_003", "RSA-2048", "2025-01-07", "Revoked"),
        ]
        for row, (key_id, key_type, created, status) in enumerate(dummy_data):
            self.key_list.insertRow(row)
            self.key_list.setItem(row, 0, QTableWidgetItem(key_id))
            self.key_list.setItem(row, 1, QTableWidgetItem(key_type))
            self.key_list.setItem(row, 2, QTableWidgetItem(created))
            self.key_list.setItem(row, 3, QTableWidgetItem(status))

class SecureNotesWidget(QWidget):
    def __init__(self, cryptosystem):
        super().__init__()
        self.cryptosystem = cryptosystem
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Category Selection
        category_layout = QHBoxLayout()
        self.category_label = QLabel("Category:")
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.currentTextChanged.connect(self.load_notes)
        category_layout.addWidget(self.category_label)
        category_layout.addWidget(self.category_combo)
        layout.addLayout(category_layout)

        # Note Title
        title_layout = QHBoxLayout()
        self.title_label = QLabel("Title:")
        self.title_input = QLineEdit()
        title_layout.addWidget(self.title_label)
        title_layout.addWidget(self.title_input)
        layout.addLayout(title_layout)

        # Note Content
        self.content_label = QLabel("Note Content:")
        self.content_text = QTextEdit()
        layout.addWidget(self.content_label)
        layout.addWidget(self.content_text)

        # Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Note")
        self.save_btn.clicked.connect(self.save_note)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_fields)
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)

        # Notes List
        self.notes_list = QTableWidget()
        self.notes_list.setColumnCount(4)
        self.notes_list.setHorizontalHeaderLabels(["Title", "Category", "Created", "Actions"])
        self.notes_list.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.notes_list)

        self.setLayout(layout)
        self.refresh_categories()
        self.load_notes()

    def refresh_categories(self):
        current_text = self.category_combo.currentText()
        self.category_combo.clear()
        categories = set()
        for category in self.cryptosystem.password_manager.secure_notes.keys():
            categories.add(category)
        self.category_combo.addItems(sorted(categories))
        if current_text:
            index = self.category_combo.findText(current_text)
            if index >= 0:
                self.category_combo.setCurrentIndex(index)

    def load_notes(self):
        self.notes_list.setRowCount(0)
        category = self.category_combo.currentText()
        if not category:
            return

        notes = self.cryptosystem.password_manager.secure_notes.get(category, {})
        for title, note_data in notes.items():
            row = self.notes_list.rowCount()
            self.notes_list.insertRow(row)
            
            # Add note details
            self.notes_list.setItem(row, 0, QTableWidgetItem(title))
            self.notes_list.setItem(row, 1, QTableWidgetItem(category))
            self.notes_list.setItem(row, 2, QTableWidgetItem(note_data['created']))
            
            # Add action buttons
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)
            
            view_btn = QPushButton("View")
            view_btn.clicked.connect(lambda checked, t=title, c=category: self.view_note(c, t))
            
            delete_btn = QPushButton("Delete")
            delete_btn.clicked.connect(lambda checked, t=title, c=category: self.delete_note(c, t))
            
            actions_layout.addWidget(view_btn)
            actions_layout.addWidget(delete_btn)
            actions_widget.setLayout(actions_layout)
            
            self.notes_list.setCellWidget(row, 3, actions_widget)

    def save_note(self):
        category = self.category_combo.currentText()
        title = self.title_input.text()
        content = self.content_text.toPlainText()

        if not all([category, title, content]):
            QMessageBox.warning(self, "Input Error", "Please fill in all fields")
            return

        try:
            self.cryptosystem.password_manager.save_secure_note(category, title, content)
            QMessageBox.information(self, "Success", "Note saved successfully!")
            self.clear_fields()
            self.refresh_categories()
            self.load_notes()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save note: {str(e)}")

    def view_note(self, category, title):
        try:
            content = self.cryptosystem.password_manager.get_secure_note(category, title)
            self.category_combo.setCurrentText(category)
            self.title_input.setText(title)
            self.content_text.setText(content)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load note: {str(e)}")

    def delete_note(self, category, title):
        reply = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the note '{title}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if category in self.cryptosystem.password_manager.secure_notes:
                    if title in self.cryptosystem.password_manager.secure_notes[category]:
                        del self.cryptosystem.password_manager.secure_notes[category][title]
                        if not self.cryptosystem.password_manager.secure_notes[category]:
                            del self.cryptosystem.password_manager.secure_notes[category]
                        self.cryptosystem.password_manager.save_to_file()
                        self.refresh_categories()
                        self.load_notes()
                        QMessageBox.information(self, "Success", "Note deleted successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete note: {str(e)}")

    def clear_fields(self):
        self.title_input.clear()
        self.content_text.clear()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cryptosystem = AdvancedCryptosystem()
        self.init_ui()

    def init_ui(self):
        # Set window properties
        self.setWindowTitle('Advanced Cryptosystem')
        self.setGeometry(100, 100, 800, 600)
        
        # Set dark background
        self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF;")
        
        # Set window icon
        self.setWindowIcon(QIcon("C:/Users/raijm/Downloads/icon crypt.ico"))  # Update this path to your icon file
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Create tab widget
        tabs = QTabWidget()
        
        # Add tabs
        tabs.addTab(EncryptionWidget(self.cryptosystem), "Encryption")
        tabs.addTab(PasswordGeneratorWidget(self.cryptosystem), "Password Generator")
        tabs.addTab(StealthOperationsWidget(self.cryptosystem), "Stealth Operations")
        tabs.addTab(SecuritySettingsWidget(self.cryptosystem), "Security Settings")
        tabs.addTab(PasswordStorageWidget(self.cryptosystem), "Password Storage")
        tabs.addTab(KeyManagementWidget(self.cryptosystem), "Key Management")
        tabs.addTab(SecureNotesWidget(self.cryptosystem), "Secure Notes")  # Add the new tab
        tabs.addTab(InfoWidget(), "Information")

        layout.addWidget(tabs)

        # Set dark theme
        self.set_dark_theme()

    def set_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #3d3d3d;
                background: #2b2b2b;
            }
            QTabBar::tab {
                background: #3d3d3d;
                color: #ffffff;
                padding: 8px 20px;
                margin: 2px;
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #0d47a1;
            }
            QPushButton {
                background-color: #0d47a1;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:pressed {
                background-color: #0a367c;
            }
            QLineEdit, QTextEdit {
                background-color: #3d3d3d;
                color: #ffffff;
                padding: 8px;
                border: 1px solid #4d4d4d;
                border-radius: 4px;
            }
            QGroupBox {
                color: #ffffff;
                border: 1px solid #4d4d4d;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 24px;
                font-weight: bold;
            }
            QGroupBox::title {
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QProgressBar {
                border: 1px solid #4d4d4d;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                background-color: #3d3d3d;
            }
            QProgressBar::chunk {
                background-color: #0d47a1;
                border-radius: 3px;
            }
            QComboBox {
                background-color: #3d3d3d;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #4d4d4d;
                border-radius: 4px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #ffffff;
                margin-right: 8px;
            }
            QTableWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                gridline-color: #4d4d4d;
                border: 1px solid #4d4d4d;
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #0d47a1;
            }
            QHeaderView::section {
                background-color: #3d3d3d;
                color: #ffffff;
                padding: 8px;
                border: none;
            }
            QScrollBar:vertical {
                background-color: #2b2b2b;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #4d4d4d;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QCheckBox {
                color: #ffffff;
            }
            QSpinBox {
                background-color: #3d3d3d;
                color: #ffffff;
                padding: 6px;
                border: 1px solid #4d4d4d;
                border-radius: 4px;
            }
        """)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
