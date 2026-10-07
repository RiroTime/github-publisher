@echo off
setlocal
title publisher - deploy key setup

rem ---------------------------------------------------------------
rem  Create one deploy key for one GitHub repo.
rem
rem  Usage - double-click this file, or from a terminal:
rem      setup-key.cmd <key-name> <owner/repo>
rem  Example:
rem      setup-key.cmd github-deploy-my-tool alice/my-tool
rem  Run it with no arguments and it will ask you for both.
rem
rem  One deploy key can only be attached to one repo on GitHub.
rem  Two repos = run this twice, with two different key names.
rem ---------------------------------------------------------------

set "KEYNAME=%~1"
set "REPO=%~2"

set "SSHDIR=C:\Windows\System32\OpenSSH"
set "KEYDIR=%~dp0keys"

if exist "%SSHDIR%\ssh-keygen.exe" goto have_ssh
echo ERROR: ssh-keygen.exe not found at %SSHDIR%
echo Install it: Settings - Apps - Optional features - OpenSSH Client
echo Or set SSHDIR at the top of this file to where ssh-keygen.exe lives.
pause
exit /b 1

:have_ssh
if "%KEYNAME%"=="" set /p "KEYNAME=Key name (e.g. github-deploy-my-tool): "
if "%REPO%"=="" set /p "REPO=Repo slug (owner/name, e.g. alice/my-tool): "

if "%KEYNAME%"=="" (
  echo ERROR: key name cannot be empty.
  pause
  exit /b 1
)

set "KEY=%KEYDIR%\%KEYNAME%"

echo ================================================================
echo  deploy key setup  -  %KEYNAME%
echo  for repo            %REPO%
echo ================================================================
echo.

if not exist "%KEYDIR%" mkdir "%KEYDIR%"

if exist "%KEY%" goto load

echo [1/2] Generating an ed25519 deploy key.
echo       You will be asked for a passphrase. SET ONE. Do not leave it empty.
echo       You set it ONCE here, then reuse that SAME passphrase every time the
echo       key is loaded into ssh-agent. It is not a new password per run.
echo       That passphrase is the root of the whole boundary: without it,
echo       anyone who can read the key file can push.
echo.
"%SSHDIR%\ssh-keygen.exe" -t ed25519 -C "%KEYNAME%" -f "%KEY%"
if errorlevel 1 goto fail
"%SSHDIR%\ssh-keygen.exe" -y -P "" -f "%KEY%" >nul 2>&1
if not errorlevel 1 goto nopass
echo.

:load
echo [2/2] Loading the key into ssh-agent.
echo       Enter the SAME passphrase you set in step 1. This just unlocks the
echo       key for the current login session - it is NOT a new password.
echo.
"%SSHDIR%\ssh-add.exe" "%KEY%"
if errorlevel 1 goto fail
echo.
echo ---------- identities currently in ssh-agent ----------
"%SSHDIR%\ssh-add.exe" -l
echo -------------------------------------------------------
echo.
echo NEXT - in your browser:
echo   1. open https://github.com/%REPO%/settings/keys
echo   2. click "Add deploy key"
echo   3. paste the line below into the Key box
echo   4. tick "Allow write access"  -  without it the key is read-only and push fails
echo   5. click "Add key"
echo.
echo ---------- your public key - copy this whole line ----------
type "%KEY%.pub"
echo ------------------------------------------------------------
echo.
echo When done, close this window and run: publisher doctor
echo.
pause
exit /b 0

:nopass
echo.
echo STOP - the key just created has NO passphrase.
echo A key without a passphrase is not a boundary at all:
echo anyone who can read the file can push with it.
echo Deleting it now. Run this file again and SET A PASSPHRASE.
echo.
del "%KEY%" "%KEY%.pub"
pause
exit /b 1

:fail
echo.
echo Setup FAILED. Nothing was pushed, nothing changed on GitHub.
echo Read the error above. If you left the passphrase empty, delete
echo   %KEY%
echo and run this file again.
echo.
pause
exit /b 1
