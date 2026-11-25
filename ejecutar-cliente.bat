@echo off
cd /d "%~dp0"
if not exist out\cliente call compilar.bat
start "" javaw -Djavax.net.ssl.trustStore=certs\truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit -Djavax.net.ssl.trustStoreType=PKCS12 -cp out\cliente cliente.MainCliente
