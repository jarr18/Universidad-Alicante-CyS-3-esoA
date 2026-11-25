#!/bin/sh
cd "$(dirname "$0")"
[ -d out/servidor ] || sh ./compilar.sh
[ -f certs/servidor.p12 ] || sh ./generar-certificado.sh
exec java -cp out/servidor servidor.ServidorMain --puerto 8443 --datos datos-servidor --tls certs/servidor.p12 changeit
