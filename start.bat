@echo off
cd /d %~dp0
echo Starting node-tester at http://localhost:3000 ...
echo Keep this window open while you use it. Press Ctrl+C to stop.
node server.js
pause
