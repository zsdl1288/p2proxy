@echo off
rem Run on B (exit node). The shared key is read from key.txt next to p2proxy.exe.
rem The loop restarts p2proxy after a crash or a self-update.
cd /d "%~dp0"
set P2PX_SUPERVISED=1
:loop
rem Full path: cmd may be set not to search the current directory.
"%~dp0p2proxy.exe" server
echo p2proxy exited, restarting in 3 seconds...
ping -n 4 127.0.0.1 >nul
goto loop
