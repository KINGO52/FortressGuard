"""
Core cryptographic functionality for FortressGuard
"""

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

# Cryptography imports
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Image processing
from PIL import Image

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

class NetworkThread(threading.Thread):
    def __init__(self, host, port, callback=None, error_callback=None):
        super().__init__()
        self.host = host
        self.port = port
        self.callback = callback
        self.error_callback = error_callback
        self.running = True
        
    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(1)
            sock.settimeout(1.0)
            
            while self.running:
                try:
                    conn, addr = sock.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data and self.callback:
                            message = data.decode('utf-8')
                            self.callback(f"Received: {message} from {addr}")
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.error_callback:
                        self.error_callback(f"Connection error: {str(e)}")
                    
        except Exception as e:
            if self.error_callback:
                self.error_callback(f"Network error: {str(e)}")
        finally:
            sock.close()
            
    def stop(self):
        self.running = False

class AdvancedCryptosystem:
    def __init__(self, config):
        self.config = config
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(config.logs_dir, 'cryptosystem.log'))
            ]
        )
        
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
        
        # Initialize network thread
        self.network_thread = NetworkThread('localhost', 12345)
        self.network_thread.start()
        
        # Initialize password manager
        self.password_manager = PasswordManager(config.passwords_file)

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
            raw = base64.b64decode(data)
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
        try:
            with open(input_path, 'rb') as input_file:
                data = input_file.read()
                if progress_callback:
                    progress_callback(0.3)

            b64_data = base64.b64encode(data).decode()
            if progress_callback:
                progress_callback(0.5)

            encrypted_data = self.encrypt(b64_data)
            if progress_callback:
                progress_callback(0.7)

            with open(output_path, 'w') as output_file:
                output_file.write(encrypted_data)
                if progress_callback:
                    progress_callback(1.0)

        except Exception as e:
            logging.error(f"File encryption failed: {str(e)}")
            raise

    def decrypt_file(self, input_path, output_path, progress_callback=None):
        try:
            with open(input_path, 'r') as input_file:
                encrypted_data = input_file.read()
                if progress_callback:
                    progress_callback(0.3)

            decrypted_b64 = self.decrypt(encrypted_data)
            if progress_callback:
                progress_callback(0.5)

            decrypted_data = base64.b64decode(decrypted_b64)
            if progress_callback:
                progress_callback(0.7)

            with open(output_path, 'wb') as output_file:
                output_file.write(decrypted_data)
                if progress_callback:
                    progress_callback(1.0)

        except Exception as e:
            logging.error(f"File decryption failed: {str(e)}")
            raise

    def store_password(self, service, username, password):
        try:
            self.password_manager.save_password(service, username, password)
            logging.info(f"Stored password for {service} - {username}")
        except Exception as e:
            logging.error(f"Failed to store password: {str(e)}")

    def retrieve_password(self, service, username):
        return self.password_manager.retrieve_password(service, username)

    def list_passwords(self):
        return self.password_manager.list_passwords()

    def delete_password(self, service, username):
        self.password_manager.delete_password(service, username)

    def analyze_password_strength(self, password, paranoid_mode=False):
        """Analyze password strength using multiple criteria"""
        score = 0
        feedback = []
        recommendations = []

        try:
            # Length check with paranoid mode consideration
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

            # Character variety checks
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
                    symbol_count = sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?/")
                    if symbol_count < 2:
                        recommendations.append("Paranoid mode: Use multiple special characters")
                else:
                    score -= 15
                    feedback.append("Missing special characters (required in paranoid mode)")
                    recommendations.append("Add special characters (!@#$%^&* etc.)")
            else:
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

            # Check for common patterns
            patterns_found = []

            if re.search(r'(.)\1{2,}', password):
                penalty = 25 if paranoid_mode else 15
                score -= penalty
                patterns_found.append("repeated characters")

            if (re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', 
                         password.lower()) or
                re.search(r'(012|123|234|345|456|567|678|789)', password)):
                penalty = 20 if paranoid_mode else 10
                score -= penalty
                patterns_found.append("sequential characters")

            keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn']
            if any(pattern in password.lower() for pattern in keyboard_patterns):
                penalty = 25 if paranoid_mode else 15
                score -= penalty
                patterns_found.append("keyboard patterns")

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

            # Calculate entropy
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

            # Determine strength category
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
        try:
            if not os.path.exists(image_path):
                raise ValueError("Image file does not exist")
            
            img = Image.open(image_path)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            width, height = img.size
            max_bytes = (width * height * 3) // 8
            
            binary_data = ''.join(format(ord(i), '08b') for i in data)
            binary_data += '0' * 8
            
            if len(binary_data) > max_bytes * 8:
                raise ValueError(f"Image too small to hide this data. Maximum size: {max_bytes} bytes")

            pixels = list(img.getdata())
            pixel_count = len(pixels)
            modified_pixels = []
            data_index = 0
            
            for i in range(pixel_count):
                if data_index < len(binary_data):
                    r, g, b = pixels[i]
                    
                    if data_index < len(binary_data):
                        r = (r & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    if data_index < len(binary_data):
                        g = (g & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    if data_index < len(binary_data):
                        b = (b & ~1) | int(binary_data[data_index])
                        data_index += 1
                    
                    modified_pixels.append((r, g, b))
                else:
                    modified_pixels.append(pixels[i])
            
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(modified_pixels)
            
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            output_path = os.path.splitext(output_path)[0] + '.png'
            new_img.save(output_path, 'PNG')
            
            verification = self.extract_data_from_image(output_path)
            if verification != data:
                raise ValueError("Data verification failed")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to hide data in image: {str(e)}")
            raise

    def extract_data_from_image(self, image_path):
        try:
            if not os.path.exists(image_path):
                raise ValueError("Image file does not exist")
            
            img = Image.open(image_path)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            pixels = list(img.getdata())
            
            binary_data = ''
            for pixel in pixels:
                r, g, b = pixel
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
            
            data = ''
            for i in range(0, len(binary_data), 8):
                byte = binary_data[i:i+8]
                if byte == '00000000':
                    break
                if len(byte) == 8:
                    data += chr(int(byte, 2))
            
            return data
            
        except Exception as e:
            logging.error(f"Failed to extract data from image: {str(e)}")
            raise

    def secure_delete_file(self, file_path, passes=7, progress_callback=None):
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError("File not found")
            
            file_size = os.path.getsize(file_path)
            
            for pass_num in range(passes):
                with open(file_path, 'wb') as f:
                    if pass_num == 0:
                        pattern = b'\x00'
                    elif pass_num == passes - 1:
                        pattern = b'\xFF'
                    else:
                        pattern = os.urandom(1)
                    
                    chunk_size = 4096
                    remaining = file_size
                    
                    while remaining > 0:
                        write_size = min(chunk_size, remaining)
                        f.write(pattern * write_size)
                        remaining -= write_size
                        
                        if progress_callback:
                            total_progress = (pass_num + (file_size - remaining) / file_size) / passes
                            progress_callback(total_progress)
                
                os.fsync(f.fileno())
            
            os.remove(file_path)
            
        except Exception as e:
            logging.error(f"Failed to securely delete file: {e}")
            raise

    def emergency_destruction(self):
        try:
            self.key = None
            self.password = None
            self.salt = None
            
            self.password_manager.delete_passwords()
            
            if hasattr(self, 'network_thread'):
                self.network_thread.stop()
            
            config_files = [
                os.path.join(self.config.config_dir, 'config.ini'),
                os.path.join(self.config.logs_dir, 'cryptosystem.log'),
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
        key = RSA.generate(2048)
        self.triple_keys[CipherMode.RSA] = key.export_key()

    def save_key(self, key):
        key_path = os.path.join(self.config.keys_dir, 'key.bin')
        with open(key_path, 'wb') as key_file:
            key_file.write(key)

    def load_key(self):
        key_path = os.path.join(self.config.keys_dir, 'key.bin')
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                return key_file.read()
        return None

    def debug_keys(self):
        try:
            for mode, key in self.triple_keys.items():
                if not key:
                    logging.info(f"Key for {mode}: Missing")
        except Exception as e:
            logging.error(f"Error checking keys: {str(e)}")

    def save_specific_key(self, filename, key):
        try:
            key_path = os.path.join(self.config.keys_dir, filename)
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
        except Exception as e:
            logging.error(f"Failed to save key {filename}: {str(e)}")

    def load_specific_key(self, filename):
        try:
            key_path = os.path.join(self.config.keys_dir, filename)
            if os.path.exists(key_path):
                with open(key_path, 'rb') as key_file:
                    return key_file.read()
        except Exception as e:
            logging.error(f"Failed to load key {filename}: {str(e)}")
        return None 