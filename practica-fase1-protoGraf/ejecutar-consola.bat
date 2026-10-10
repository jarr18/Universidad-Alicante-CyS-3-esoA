@echo off
rem Compila y lanza la version de consola (requiere JDK 17 o superior en el PATH)
if not exist out mkdir out
javac -encoding UTF-8 -sourcepath src -d out src\MainGui.java src\Main.java
if errorlevel 1 (
  echo Error de compilacion.
  pause
  exit /b 1
)
java -cp out Main
pause
