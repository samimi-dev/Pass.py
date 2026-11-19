@echo off
title Pass.py - Portable Windows Build
cd /d "%~dp0"
echo ============================================================
echo   Pass.py - Portable Windows Build (Anti-False-Positive)
echo ============================================================
echo Folder: %CD%
echo.

set "PY="
python -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY=python"
if not defined PY py -3 -c "import sys" >nul 2>&1
if not defined PY if not errorlevel 1 set "PY=py -3"
if not defined PY py -c "import sys" >nul 2>&1
if not defined PY if not errorlevel 1 set "PY=py"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python314\python.exe" set PY="%LocalAppData%\Programs\Python\Python314\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set PY="%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set PY="%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set PY="%LocalAppData%\Programs\Python\Python311\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python310\python.exe" set PY="%LocalAppData%\Programs\Python\Python310\python.exe"
if not defined PY if exist "%LocalAppData%\Programs\Python\Python39\python.exe" set PY="%LocalAppData%\Programs\Python\Python39\python.exe"
if not defined PY if exist "C:\Python313\python.exe" set PY="C:\Python313\python.exe"
if not defined PY if exist "C:\Python312\python.exe" set PY="C:\Python312\python.exe"
if not defined PY if exist "C:\Python311\python.exe" set PY="C:\Python311\python.exe"
if not defined PY if exist "C:\Python310\python.exe" set PY="C:\Python310\python.exe"

set "OK=1"
if not exist "Pass.py" echo [ERROR] Pass.py not found in %CD%
if not exist "Pass.py" set "OK="
if not defined PY echo [ERROR] Python 3 was not found. Install Python 3.9+ from python.org and enable "Add python.exe to PATH".
if not defined PY set "OK="

if defined OK echo Using Python: %PY%
if defined OK %PY% --version
if defined OK echo.
if defined OK echo Checking Tkinter GUI support...
if defined OK %PY% -c "import tkinter"
if defined OK if errorlevel 1 echo [ERROR] Tkinter is missing. Re-run the Python installer and enable "tcl/tk and IDLE".
if defined OK if errorlevel 1 set "OK="

if defined OK echo.
if defined OK echo Installing cryptography, pillow, and pyinstaller...
if defined OK %PY% -m pip install --upgrade cryptography pillow pyinstaller
if defined OK if errorlevel 1 echo [ERROR] pip failed to install required packages.
if defined OK if errorlevel 1 set "OK="

if defined OK if not exist "build" mkdir "build"
if defined OK set "ICON_ARG="
if defined OK %PY% -c "import base64,io;from PIL import Image;from pass_vault.assets import EMBEDDED_ICONS;Image.open(io.BytesIO(base64.b64decode(EMBEDDED_ICONS['appIcon']))).convert('RGBA').save('build/pass_icon.ico',format='ICO',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64)])" >nul 2>&1
if defined OK if exist "build\pass_icon.ico" set "ICON_ARG=--icon=build\pass_icon.ico"

if defined OK set "VER_ARG="
if defined OK %PY% -c "open('build/version_info.txt','w',encoding='utf-8').write('VSVersionInfo(ffi=FixedFileInfo(filevers=(1,1,0,0),prodvers=(1,1,0,0),mask=0x3f,flags=0x0,OS=0x40004,fileType=0x1,subtype=0x0,date=(0,0)),kids=[StringFileInfo([StringTable(\'040904B0\',[StringStruct(\'CompanyName\',\'samimi-dev\'),StringStruct(\'FileDescription\',\'Pass.py Offline Encrypted Password Manager\'),StringStruct(\'FileVersion\',\'1.1.0.0\'),StringStruct(\'InternalName\',\'Pass\'),StringStruct(\'LegalCopyright\',\'Copyright (c) 2026 samimi-dev\'),StringStruct(\'OriginalFilename\',\'Pass.exe\'),StringStruct(\'ProductName\',\'Pass.py\'),StringStruct(\'ProductVersion\',\'1.1.0.0\')])]),VarFileInfo([VarStruct(\'Translation\',[1033,1200])])])')" >nul 2>&1
if defined OK if exist "build\version_info.txt" set "VER_ARG=--version-file=build\version_info.txt"

if defined OK echo.
if defined OK echo Building portable folder dist\Pass\ (--onedir --noupx)...
if defined OK %PY% -m PyInstaller --noconfirm --clean --onedir --noupx --windowed --name Pass %ICON_ARG% %VER_ARG% --collect-submodules pass_vault --hidden-import=cryptography --hidden-import=PIL.ImageTk --hidden-import=PIL.ImageOps --hidden-import=PIL.ImageDraw Pass.py
if defined OK if errorlevel 1 echo [ERROR] PyInstaller failed to build Pass.exe.
if defined OK if errorlevel 1 set "OK="

if defined OK if not exist "dist\Pass\Pass.exe" echo [ERROR] dist\Pass\Pass.exe was not found (check Windows Defender / Antivirus).
if defined OK if not exist "dist\Pass\Pass.exe" set "OK="

if defined OK echo.
if defined OK echo Creating portable release archive dist\Pass-v1.1.0-Windows-Portable.zip...
if defined OK %PY% -c "import shutil; shutil.make_archive('dist/Pass-v1.1.0-Windows-Portable', 'zip', 'dist', 'Pass')"
if defined OK if errorlevel 1 echo [WARNING] Could not create zip archive, but dist\Pass\Pass.exe is ready.

if defined OK echo.
if defined OK echo ============================================================
if defined OK echo   SUCCESS! Portable build ready:
if defined OK echo   Folder : %CD%\dist\Pass\Pass.exe
if defined OK echo   Release: %CD%\dist\Pass-v1.1.0-Windows-Portable.zip
if defined OK echo ============================================================
if not defined OK echo.
if not defined OK echo Build did NOT complete. Review the error message above.

echo.
pause
