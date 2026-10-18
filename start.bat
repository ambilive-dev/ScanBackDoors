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

echo Scan Backdoors: starting the local server. The GUI opens in your browser.
echo Bookmark http://127.0.0.1:8765/ to come back to it.
echo Keep this window open while you work. Close it, or use "Quit server" in the page, to stop.
echo.
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
echo The server exited with an error. See the message above.
echo If Windows opened the Microsoft Store, install Python from python.org instead.
echo To use another port run:  py -3 scan_backdoors_gui.py --port 9000
pause
exit /b 1
