@echo off
cd /d "%~dp0"
if not exist certs mkdir certs
del /q certs\servidor.p12 certs\truststore.p12 certs\servidor.cer 2>nul
keytool -genkeypair -alias cys -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore certs\servidor.p12 -storepass changeit -dname "CN=localhost" -ext "san=dns:localhost,ip:127.0.0.1" -validity 365
keytool -exportcert -alias cys -keystore certs\servidor.p12 -storepass changeit -file certs\servidor.cer
keytool -importcert -alias cys -file certs\servidor.cer -keystore certs\truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
echo Certificado generado en certs\
