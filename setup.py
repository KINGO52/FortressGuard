from setuptools import setup, find_packages
import os
import sys
from pathlib import Path
import shutil

def create_config_directories():
    """Create necessary directories for the application"""
    # Get user's home directory
    home_dir = Path.home()
    
    # Create main app directory
    app_dir = home_dir / '.fortressguard'
    app_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (app_dir / 'keys').mkdir(exist_ok=True)
    (app_dir / 'logs').mkdir(exist_ok=True)
    (app_dir / 'config').mkdir(exist_ok=True)
    
    # Copy icon if it exists in current directory
    icon_path = Path(__file__).parent / 'icon_crypt.ico'
    if icon_path.exists():
        shutil.copy(icon_path, app_dir / 'icon_crypt.ico')
    
    return str(app_dir)

def write_config(app_dir):
    """Write initial configuration file"""
    config_path = Path(app_dir) / 'config' / 'config.ini'
    with open(config_path, 'w') as f:
        f.write(f"""[Paths]
app_dir = {app_dir}
keys_dir = {app_dir}/keys
logs_dir = {app_dir}/logs
config_dir = {app_dir}/config
passwords_file = {app_dir}/passwords.json
icon_path = {app_dir}/icon_crypt.ico

[Security]
key_rotation_days = 90
paranoid_mode = false
auto_backup = true
""")

def read_readme():
    """Read README.md with UTF-8 encoding"""
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Warning: Could not read README.md: {e}")
        return "FortressGuard - A secure encryption and password management system"

def main():
    app_dir = create_config_directories()
    write_config(app_dir)
    
    setup(
        name="fortressguard",
        version="1.0.0",
        packages=find_packages(),
        install_requires=[
            'PyQt5>=5.15.0',
            'pycryptodome>=3.10.1',
            'Pillow>=8.0.0',
            'configparser>=5.0.0',
        ],
        entry_points={
            'console_scripts': [
                'fortressguard=fortressguard.main:main',
            ],
        },
        author="Your Name",
        author_email="your.email@example.com",
        description="A secure encryption and password management system",
        long_description=read_readme(),
        long_description_content_type="text/markdown",
        url="https://github.com/yourusername/fortressguard",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        python_requires='>=3.7',
    )

if __name__ == "__main__":
    main() 