@echo off
cd /d "%~dp0"
if exist out rmdir /s /q out
mkdir out\servidor out\cliente out\pruebas
dir /s /b comun\src\*.java servidor\src\*.java > out\fuentes-servidor.txt
javac -d out\servidor @out\fuentes-servidor.txt || goto error
dir /s /b comun\src\*.java cliente\src\*.java > out\fuentes-cliente.txt
javac -d out\cliente @out\fuentes-cliente.txt || goto error
dir /s /b pruebas\src\*.java > out\fuentes-pruebas.txt
javac -cp out\servidor;out\cliente -d out\pruebas @out\fuentes-pruebas.txt || goto error
echo Compilacion correcta (carpeta out\)
goto fin
:error
echo ERROR de compilacion. Necesitas un JDK 17 o superior (javac).
:fin
