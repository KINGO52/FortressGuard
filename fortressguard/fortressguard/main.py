import sys
import os
from pathlib import Path

# Add parent directory to path to import config_manager
sys.path.append(str(Path(__file__).parent.parent))
from fortressguard.config_manager import ConfigManager

# Import the original code but use ConfigManager for paths
from PyQt5.QtWidgets import QApplication
from .cryptosystem import AdvancedCryptosystem
from .ui.main_window import MainWindow

def main():
    try:
        # Initialize configuration
        config = ConfigManager()
        
        # Create application
        app = QApplication(sys.argv)
        
        # Create main cryptosystem with configuration
        cryptosystem = AdvancedCryptosystem(config)
        
        # Create and show main window
        window = MainWindow(cryptosystem)
        window.show()
        
        # Run application
        sys.exit(app.exec_())
        
    except FileNotFoundError as e:
        print("Error: Configuration not found. Please run setup.py first.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 