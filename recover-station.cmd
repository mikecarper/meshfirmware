@echo off
setlocal
where py.exe >nul 2>&1
if errorlevel 1 goto python
py -3 "%~dp0tools\station_recovery.py" %*
set "result=%errorlevel%"
goto done
:python
where python.exe >nul 2>&1
if errorlevel 1 goto missing
python "%~dp0tools\station_recovery.py" %*
set "result=%errorlevel%"
goto done
:missing
echo Install Python 3.10 or newer from https://www.python.org/downloads/ and run again.
set "result=1"
:done
if "%~1"=="" pause
exit /b %result%
