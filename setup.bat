@echo off
echo Setting up FortressGuard...

:: Uninstall existing crypto packages to avoid conflicts
echo Cleaning up existing installations...
python -m pip uninstall -y pycrypto
python -m pip uninstall -y pycryptodome

:: Install required packages
echo Installing required packages...
python -m pip install pycryptodome==3.19.0
python -m pip install PyQt5>=5.15.0
python -m pip install Pillow>=8.0.0
python -m pip install configparser>=5.0.0

:: Install the package in development mode
echo Installing FortressGuard...
python setup.py develop --user

echo Setup complete! You can now run FortressGuard using: python -m fortressguard you can also click on open.bat
pause 
