@echo off
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY goto :nopython

%PY% scan_backdoors_gui.py
if errorlevel 1 goto :failed
exit /b 0

:nopython
echo Python 3.6 or newer was not found.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
pause
exit /b 1

:failed
echo.
echo The GUI exited with an error. See the message above.
echo If the error mentions tkinter, reinstall Python and keep the "tcl/tk and IDLE" option enabled.
echo If Windows opened the Microsoft Store, install Python from python.org instead.
pause
exit /b 1
