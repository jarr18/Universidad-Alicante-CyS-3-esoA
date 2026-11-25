#!/bin/sh
cd "$(dirname "$0")"
[ -d out/pruebas ] || sh ./compilar.sh
[ -f certs/servidor.p12 ] || sh ./generar-certificado.sh
echo "=== Pruebas con TLS ==="
java -Djavax.net.ssl.trustStore=certs/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit \
  -Djavax.net.ssl.trustStoreType=PKCS12 -cp out/servidor:out/cliente:out/pruebas pruebas.PruebaIntegral certs/servidor.p12 changeit
