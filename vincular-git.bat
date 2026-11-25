@echo off
chcp 65001 >nul
rem ============================================================
rem  Vincula esta carpeta con el repositorio de GitHub
rem  jarr18/Universidad-Alicante-CyS-3-esoA (rama main)
rem  No modifica ni borra ninguno de tus archivos del proyecto.
rem ============================================================
cd /d "%~dp0"

git --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Git no esta instalado. Descargalo de https://git-scm.com/download/win
  pause
  exit /b 1
)

if exist ".git" (
  echo Ya existe un repositorio .git en esta carpeta; solo se ajusta el remoto.
) else (
  git init
)

git remote remove origin >nul 2>&1
git remote add origin https://github.com/jarr18/Universidad-Alicante-CyS-3-esoA.git

echo Descargando historial de GitHub...
git fetch origin
if errorlevel 1 (
  echo [ERROR] No se pudo descargar el repositorio. Revisa tu conexion.
  pause
  exit /b 1
)

rem Apunta la rama main al ultimo commit de GitHub SIN tocar tus archivos
git symbolic-ref HEAD refs/heads/main
git update-ref refs/heads/main origin/main
git reset -q
git branch -u origin/main main

rem Identidad para los commits (solo si no tienes una global ya configurada)
git config user.name >nul 2>&1 || git config user.name "jarr18"
git config user.email >nul 2>&1 || git config user.email "jarr18@users.noreply.github.com"

rem Que este script no se suba al repositorio
echo vincular-git.bat>> ".git\info\exclude"

echo.
echo ============================================================
echo  Listo. Estado actual (cambios de la Fase 2 respecto a GitHub):
echo ============================================================
git status -sb
echo.
echo Ahora en VS Code: Control de codigo fuente ^> escribe un mensaje ^> Commit ^> Sync/Push.
pause
