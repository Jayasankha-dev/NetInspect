@echo off
setlocal
cd /d "%~dp0"
echo ============================================
echo NetInspect Advanced Binary Analyzer 4.0
echo ============================================
py -m pip install -r requirements.txt || goto :fail
py -m py_compile netinspect.py || goto :fail
py -m pip install pyinstaller || goto :fail
py -m PyInstaller --clean --noconfirm --onefile --windowed --name NetInspect-Advanced netinspect.py || goto :fail
echo.
echo BUILD COMPLETE:
echo %CD%\dist\NetInspect-Advanced.exe
pause
exit /b 0
:fail
echo BUILD FAILED.
pause
exit /b 1
