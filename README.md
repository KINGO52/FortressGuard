# FortressGuard Cryptosystem

[![Python application](https://github.com/KINGO52/FortressGuard/actions/workflows/python-app.yml/badge.svg)](https://github.com/KINGO52/FortressGuard/actions/workflows/python-app.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/fortressguard.svg)](https://badge.fury.io/py/fortressguard)

A state-of-the-art encryption and security suite that combines military-grade encryption with an intuitive dark-themed interface. FortressGuard provides comprehensive protection for your sensitive data through advanced cryptographic algorithms, intelligent password management, and innovative security features.

## 🛡️ Key Features

- **Advanced Encryption Suite**
  - AES-CBC (256-bit)
  - ChaCha20 Stream Cipher
  - RSA Public Key Cryptography
  
- **Intelligent Password Management**
  - Smart password generation
  - Real-time strength analysis
  - Advanced brute-force time estimation
  - Secure password vault
  
- **Enhanced Security Tools**
  - Steganography capabilities
  - Military-grade secure deletion
  - Protected secure notes
  - Emergency destruction protocol
  
- **Modern Interface**
  - Sleek dark-themed UI
  - Real-time feedback
  - Intuitive controls
  - Progress monitoring

## 🔧 Requirements

- Python 3.7+
- PyQt5
- pycryptodome
- Pillow

## 🚀 Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/KINGO52/FortressGuard.git
cd FortressGuard
```

2. Install the package in development mode:
```bash
python setup.py develop
```

This will:
- Create necessary directories in your home folder (`~/.fortressguard`)
- Set up configuration files
- Install required dependencies
- Configure paths for your system

3. Verify installation:
```bash
python -m FortressGuard
```

The application should launch with all paths properly configured.

### Directory Structure After Setup:
```
~/.fortressguard/           # Application data directory
├── config/                 # Configuration files
│   └── config.ini         # Main configuration
├── keys/                  # Encryption keys
├── logs/                  # Application logs
└── passwords.json         # Encrypted password database
```

### For Developers

If you're developing or modifying the code:

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install in development mode:
```bash
pip install -e .
```

3. Run tests:
```bash
python -m pytest tests/
```

## 💻 Usage

Launch FortressGuard using either:
```bash
# If installed via setup.py
fortressguard

# Or directly via Python
python -m fortressguard
```

## 🔐 Security Features

- Military-grade encryption algorithms
- Advanced password strength analysis
- Sophisticated brute force protection
- Secure memory management
- Comprehensive audit logging
- Zero-knowledge architecture

## 🌟 Why FortressGuard?

FortressGuard stands out with its combination of powerful security features and user-friendly interface. Whether you're protecting personal data or managing enterprise secrets, FortressGuard provides the tools and confidence you need for robust digital security.

## 📜 License

MIT License - See LICENSE file for details 
