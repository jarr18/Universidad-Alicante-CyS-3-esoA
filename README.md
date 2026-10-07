# Práctica Fase I — Compresión y Seguridad (versión sin base de datos)

Versión simplificada del proyecto: **sin MySQL ni ninguna dependencia
externa**. Todo se guarda en dos ficheros de texto plano dentro de la
carpeta `data/`, que se crea automáticamente la primera vez que
ejecutas el programa.

- `data/usuarios.txt` → un usuario por línea
- `data/archivos.txt` → un archivo cifrado por línea (registro y clave
  protegida; el contenido cifrado va en un fichero `.enc` aparte)

Los datos binarios (claves, IVs) se guardan
codificados en **Base64** dentro de cada línea, separados por `|`.
Nada se guarda nunca en claro salvo el nombre de usuario y el nombre
del archivo.

## Lógica implementada (según el diagrama del PDF)

- Cada archivo `f_i` se cifra con una clave AES-128 propia `k_fi`:
  `E^AES_{k_fi}(f_i) = c_i`
- Esa clave `k_fi` se protege cifrándola con la clave pública RSA del
  usuario: `E^RSA_{Ku}(k_fi)`
- La clave privada RSA del usuario `k_u` se protege cifrándola con
  AES-128, usando como clave el hash `SHA3-256(p_u)` del password del
  usuario, truncado a 128 bits: `E^AES_{SHA3-256(p_u)}(k_u)`
- El password **nunca se guarda**, ni siquiera su hash: solo se usa
  para derivar la clave AES en el momento (registro/login). El login
  se valida indirectamente: si el descifrado de la clave privada tiene
  éxito, el password era correcto.

## Estructura del proyecto

```
practica-fase1-simple/
└── src/
    ├── Main.java                    # Menú de línea de comandos (todo el flujo)
    ├── crypto/
    │   ├── AesUtil.java             # AES-128 CTR (sin padding)
    │   ├── RsaUtil.java             # RSA-2048
    │   └── HashUtil.java            # SHA3-256 (nativo desde Java 9, sin librerías)
    ├── model/
    │   ├── Usuario.java
    │   └── ArchivoCifrado.java
    └── storage/
        ├── UsuarioRepository.java   # Lee/escribe data/usuarios.txt
        └── ArchivoRepository.java   # Lee/escribe data/archivos.txt
```

No hay carpeta `service/` como en la versión con base de datos: al
quitar la BD, toda la lógica cabe directamente en `Main.java` sin que
resulte difícil de seguir.

## Compilar y ejecutar

Solo necesitas un **JDK 9 o superior** (no hace falta Maven ni ninguna
librería, todo es Java estándar).

```bash
# Compilar
javac -encoding UTF-8 -d out $(find src -name "*.java")

# Ejecutar
java -cp out Main
```

En Windows (PowerShell), en vez del `find` usa:

```powershell
javac -encoding UTF-8 -d out (Get-ChildItem -Recurse -Filter *.java -Path src).FullName
java -cp out Main
```

## Uso

El programa muestra un menú:

1. **Registrar usuario**: pide nombre y password, genera el par de
   claves RSA y guarda la clave privada protegida en `usuarios.txt`.
2. **Iniciar sesión**: comprueba el password intentando descifrar la
   clave privada; si falla, indica "Password incorrecto".
3. **Cifrar archivo**: pide la ruta de un archivo, genera `k_fi`, lo
   cifra y escribe el resultado como `nombre.enc` **en la misma carpeta**
   (cambia la extensión; si ya existe un `.enc` con ese nombre usa
   `nombre_2.enc`, etc.). La clave protegida `E^RSA_Ku(k_fi)` se registra
   en `archivos.txt` y **el archivo original se elimina**.
4. **Descifrar archivo**: recupera `k_fi` con la clave privada de la
   sesión, restaura el archivo original (por defecto en la carpeta del
   `.enc`, o en la que indiques; no sobrescribe si ya existe) y a
   continuación **elimina el `.enc` y borra de `archivos.txt` la clave
   protegida**. Ese archivo deja de estar disponible para descifrar:
   para volver a hacerlo hay que cifrarlo de nuevo (se genera una
   `k_fi` nueva).
5. **Listar mis archivos cifrados** (los que siguen pendientes de descifrar).
6. **Cerrar sesión**.

Al salir y volver a entrar, los usuarios y archivos siguen ahí, porque
todo quedó persistido en `data/usuarios.txt` y `data/archivos.txt`.

## Por qué CTR en vez de CBC

El PDF no especifica el modo de operación de AES, solo dice "AES128".
Este proyecto usa **CTR (Counter mode)**:

- AES no cifra el archivo directamente: cifra un contador (el IV de
  16 bytes es el valor inicial de ese contador) y el resultado se
  combina con el texto claro mediante XOR, byte a byte.
- No necesita padding: el archivo puede tener cualquier longitud,
  no hace falta rellenarlo hasta un múltiplo de 16 bytes como en CBC.
- Es paralelizable y permite acceso aleatorio al contenido cifrado
  (se podría descifrar solo un trozo del archivo sin descifrar todo
  lo anterior), algo que CBC no permite con la misma facilidad.
- Requisito importante: el par (clave, IV) nunca debe reutilizarse
  para cifrar dos datos distintos. Por eso `generarIv()` genera
  siempre un IV nuevo y aleatorio (con `SecureRandom`) en cada
  cifrado, tanto de archivos como de la clave privada del usuario.

## Ciclo de vida de un archivo

```
foto.jpg --(cifrar)--> foto.enc  + registro con E^RSA_Ku(k_f) en archivos.txt   [original borrado]
foto.enc --(descifrar)--> foto.jpg                                              [.enc y registro borrados]
```

Borrar el registro al descifrar es lo que hace efectivo el "un solo uso":
aunque alguien conservase una copia del `.enc`, sin `E^RSA_Ku(k_f)` ya no
existe forma de recuperar `k_f`.

**Compatibilidad:** el contenido cifrado ya no se guarda en Base64 dentro
de `archivos.txt`. Las líneas del formato anterior se ignoran al leer; si
tenías archivos cifrados con la versión antigua, descífralos antes de
actualizar (o empieza con un `data/` limpio).

## Ampliación futura: volver a base de datos o añadir GUI

Como la lógica criptográfica vive en `crypto/` y es independiente del
almacenamiento, si más adelante quieres volver a MySQL (o cualquier
otra BD) o añadir una interfaz gráfica, solo tendrías que sustituir
las clases de `storage/` — el resto del código no cambia.
