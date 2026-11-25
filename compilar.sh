#!/bin/sh
set -e
cd "$(dirname "$0")"
rm -rf out && mkdir -p out/servidor out/cliente out/pruebas
javac -d out/servidor comun/src/comun/*.java servidor/src/servidor/*.java
javac -d out/cliente comun/src/comun/*.java cliente/src/cliente/*.java cliente/src/cliente/crypto/*.java cliente/src/cliente/net/*.java cliente/src/cliente/gui/*.java
javac -cp out/servidor:out/cliente -d out/pruebas pruebas/src/pruebas/*.java
echo "Compilacion correcta (carpeta out/)"
