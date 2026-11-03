@echo off
python "%~dp0update.py" -p "%~1"
exit /b %errorlevel%
