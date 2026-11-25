#!/bin/sh
cd "$(dirname "$0")"
[ -d out/cliente ] || sh ./compilar.sh
exec java -Djavax.net.ssl.trustStore=certs/truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit \
  -Djavax.net.ssl.trustStoreType=PKCS12 -cp out/cliente cliente.MainCliente
