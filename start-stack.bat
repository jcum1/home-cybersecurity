@echo off
REM start-stack.bat
REM Opens Elasticsearch, Kibana, and Filebeat each in their own window.
REM Run this from the repo root: C:\Users\jcurtis1\git\home-cybersecurity\

echo Starting Elasticsearch...
start "Elasticsearch" cmd /k "elasticsearch-9.2.4\bin\elasticsearch.bat"

echo Waiting 20 seconds for Elasticsearch to initialise...
timeout /t 20 /nobreak >nul

echo Starting Kibana...
start "Kibana" cmd /k "kibana-9.2.4\bin\kibana.bat"

echo Starting Filebeat...
start "Filebeat" cmd /k "filebeat-9.2.4-windows-x86_64\filebeat.exe -e -c filebeat-9.2.4-windows-x86_64\filebeat.yml"

echo.
echo All three components started in separate windows.
echo   Elasticsearch: https://localhost:9200
echo   Kibana:        http://localhost:5601
echo.
echo NOTE: If Filebeat shows auth errors, make sure you updated the password in
echo       filebeat-9.2.4-windows-x86_64\filebeat.yml (search for CHANGE_ME).
echo       Reset the elastic password:
echo         elasticsearch-9.2.4\bin\elasticsearch-reset-password.bat -u elastic -i
echo.
pause
