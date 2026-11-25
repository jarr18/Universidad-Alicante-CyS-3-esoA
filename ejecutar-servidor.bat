@echo off
cd /d "%~dp0"
if not exist out\servidor call compilar.bat
if not exist certs\servidor.p12 call generar-certificado.bat
java -cp out\servidor servidor.ServidorMain --puerto 8443 --datos datos-servidor --tls certs\servidor.p12 changeit
pause
