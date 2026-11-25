@echo off
cd /d "%~dp0"
if not exist out\pruebas call compilar.bat
if not exist certs\servidor.p12 call generar-certificado.bat
java -Djavax.net.ssl.trustStore=certs\truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12 -cp out\servidor;out\cliente;out\pruebas pruebas.PruebaIntegral certs\servidor.p12 changeit
pause
