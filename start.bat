@echo off
title Super LOG - Enterprise MikroTik Syslog & Traffic Server
color 0b
echo ========================================================
echo         Super LOG Server (MikroTik Syslog & Accounting)
echo ========================================================
echo.
echo Starting Web Dashboard on http://localhost:8000 ...
echo Syslog UDP Server listening on port 5514 ...
echo.
echo Default Login Credentials:
echo   Username: arif
echo   Password: admin123
echo.
python server.py
pause
