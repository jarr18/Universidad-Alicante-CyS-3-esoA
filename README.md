# Práctica Fase I — Compresión y Seguridad (versión sin base de datos)

Versión simplificada del proyecto: **sin MySQL ni ninguna dependencia
externa**. Todo se guarda en dos ficheros de texto plano dentro de la
carpeta `data/`, que se crea automáticamente la primera vez que
ejecutas el programa.

- `data/usuarios.txt` → un usuario por línea
- `data/archivos.txt` → un archivo cifrado por línea

Los datos binarios (claves, IVs, contenido cifrado) se guardan
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
3. **Cifrar y subir archivo**: pide una ruta local, genera `k_fi`,
   cifra el archivo y añade una línea a `archivos.txt` con el
   contenido cifrado y la clave protegida.
4. **Descargar y descifrar archivo**: recupera `k_fi` con la clave
   privada de la sesión y descifra el archivo, guardándolo en la
   carpeta que indiques.
5. **Listar mis archivos**.
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

## Limitación a tener en cuenta

Guardar el contenido cifrado de los archivos como Base64 dentro de una
línea de texto es lo más sencillo de entender y depurar (puedes abrir
`archivos.txt` con cualquier editor y ver la estructura), pero no es
eficiente para archivos muy grandes (un vídeo de varios GB generaría
una línea enorme). Para esta práctica, con archivos de prueba
pequeños/medianos, funciona perfectamente. Si en el futuro necesitas
manejar archivos grandes, la mejora natural es guardar el contenido
cifrado en un fichero binario aparte (uno por archivo, dentro de
`data/cifrados/`) y dejar en `archivos.txt` solo la ruta a ese
fichero en vez del contenido completo.

## Ampliación futura: Añadir GUI

Como la lógica criptográfica vive en `crypto/` y es independiente del
almacenamiento, si más adelante quieres volver a MySQL (o cualquier
otra BD) o añadir una interfaz gráfica, solo tendrías que sustituir
las clases de `storage/` — el resto del código no cambia.
