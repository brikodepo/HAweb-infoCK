@echo off
title HAweb-infoCK
cd /d "%~dp0"
where node >nul 2>nul
if %errorlevel% neq 0 (
  echo.
  echo  [X] Node.js n'est pas installe !
  echo  Telecharge-le ici : https://nodejs.org/
  echo.
  pause
  exit /b 1
)
node HAweb-infoCK.js %*
pause
