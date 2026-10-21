# Práctica Fase I — Compresión y Seguridad (versión sin base de datos)

Versión simplificada del proyecto: **sin MySQL ni ninguna dependencia
externa**. Todo se guarda en dos ficheros de texto plano dentro de la
carpeta `data/`, que se crea automáticamente la primera vez que
ejecutas el programa.

- `data/usuarios.txt` → el usuario único de la Fase I (una línea)
- `data/archivos.txt` → un archivo cifrado por línea (registro y clave
  protegida; el contenido cifrado va en un fichero `.enc` aparte)

Los datos binarios (claves, IVs) se guardan
codificados en **Base64** dentro de cada línea, separados por `|`.
Nada se guarda nunca en claro salvo el nombre de usuario y el nombre
del archivo.

## Usuario único (Fase I)

Según el enunciado, en la Fase I no hace falta gestionar varios
usuarios: basta **un usuario y un password** para entrar al programa. El
alta y la autenticación de múltiples usuarios (y compartir archivos
entre ellos) corresponden a la Fase II.

Por eso **no existe opción de registro**, ni en la consola ni en la
interfaz gráfica. El usuario se crea automáticamente la primera vez que
se arranca el programa (se genera su par de claves RSA y se protege la
clave privada con su password). Las credenciales son:

| Usuario   | Password   |
|-----------|------------|
| `usuario` | `clave123` |

Se definen como constantes `USUARIO` y `PASSWORD_INICIAL` en
`service/CifradoService.java`. Para usar otro password, cámbialo ahí
**antes de la primera ejecución** (o borra la carpeta `data/` y vuelve a
arrancar; ten en cuenta que así se pierde también el registro de los
archivos ya cifrados).

## Lógica implementada (según el diagrama del PDF)

- Cada archivo `f_i` se cifra con una clave AES-128 propia `k_fi`:
  `E^AES_{k_fi}(f_i) = c_i`
- Esa clave `k_fi` se protege cifrándola con la clave pública RSA del
  usuario: `E^RSA_{Ku}(k_fi)`
- La clave privada RSA del usuario `k_u` se protege cifrándola con
  AES-128, usando como clave el hash `SHA3-256(p_u)` del password del
  usuario, truncado a 128 bits: `E^AES_{SHA3-256(p_u)}(k_u)`
- El password **nunca se guarda**, ni siquiera su hash: solo se usa
  para derivar la clave AES en el momento (creación del usuario / login).
  El login se valida indirectamente: si el descifrado de la clave privada
  tiene éxito, el password era correcto.

## Estructura del proyecto

```
practica-fase1-proto/
├── ejecutar-gui.bat / ejecutar-consola.bat   # compilar y lanzar en Windows
└── src/
    ├── MainGui.java                 # Punto de entrada de la interfaz gráfica
    ├── Main.java                    # Punto de entrada de la consola (menú)
    ├── gui/
    │   └── VentanaPrincipal.java    # Interfaz Swing (login + gestión de archivos)
    ├── service/
    │   └── CifradoService.java      # Lógica: usuario único, login, cifrar, descifrar
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

La consola (`Main`) y la interfaz gráfica (`gui`) son solo capas de
presentación: las dos delegan en `CifradoService`, que es donde vive toda
la lógica. Así el comportamiento es idéntico en ambas.

## Compilar y ejecutar

Solo necesitas un **JDK 17 o superior** (no hace falta Maven ni ninguna
librería: la interfaz usa Swing, que viene con el JDK).

**Windows:** doble clic en `ejecutar-gui.bat` (interfaz gráfica) o
`ejecutar-consola.bat` (consola).

**A mano** (Linux/macOS/Windows):

```bash
javac -encoding UTF-8 -sourcepath src -d out src/MainGui.java src/Main.java

java -cp out MainGui     # interfaz gráfica
java -cp out Main        # consola
```

## Uso

### Interfaz gráfica

1. Escribe el usuario y el password (ver tabla de credenciales arriba) y
   pulsa **Iniciar sesión** (también con Enter). La primera vez que se
   arranca el programa puede tardar un instante, porque se generan las
   claves RSA del usuario.
2. En la pantalla principal verás la lista de tus archivos cifrados:
   - **Cifrar archivo(s)…**: eliges uno o varios archivos; tras confirmar,
     cada uno se sustituye por su `.enc` y el original se elimina.
   - **Descifrar seleccionado**: eliges la fila y si restaurarlo en la
     misma carpeta o en otra. El `.enc` y su clave se eliminan.
   - **Actualizar** recarga la lista y **Cerrar sesión** vuelve al login.
3. Las operaciones lentas (cifrar ficheros grandes) se hacen en segundo
   plano y los botones se bloquean mientras tanto.

### Consola

El programa muestra un menú:

1. **Iniciar sesión**: pide usuario y password y comprueba el password
   intentando descifrar la clave privada; si falla, indica "Password
   incorrecto".
2. **Cifrar archivo**: pide la ruta de un archivo, genera `k_fi`, lo
   cifra y escribe el resultado como `nombre.enc` **en la misma carpeta**
   (cambia la extensión; si ya existe un `.enc` con ese nombre usa
   `nombre_2.enc`, etc.). La clave protegida `E^RSA_Ku(k_fi)` se registra
   en `archivos.txt` y **el archivo original se elimina**.
3. **Descifrar archivo**: recupera `k_fi` con la clave privada de la
   sesión, restaura el archivo original (por defecto en la carpeta del
   `.enc`, o en la que indiques; no sobrescribe si ya existe) y a
   continuación **elimina el `.enc` y borra de `archivos.txt` la clave
   protegida**. Ese archivo deja de estar disponible para descifrar:
   para volver a hacerlo hay que cifrarlo de nuevo (se genera una
   `k_fi` nueva).
4. **Listar mis archivos cifrados** (los que siguen pendientes de descifrar).
5. **Cerrar sesión**.

Al salir y volver a entrar, el usuario y los archivos cifrados siguen ahí,
porque todo quedó persistido en `data/usuarios.txt` y `data/archivos.txt`.

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
actualizar (o empieza con un `data/` limpio). Igualmente, si tienes un
`data/usuarios.txt` de una versión con registro y el usuario `usuario` no
existe en él, se creará uno nuevo con el password inicial; si ya existía
con otro password, borra `data/` para empezar de cero.

## Ampliación futura: Fase II

Como la lógica criptográfica vive en `crypto/` y el almacenamiento en
`storage/`, si más adelante quieres volver a MySQL (o cualquier otra BD)
solo tendrías que sustituir las clases de `storage/`: `service/`, `gui/`
y `Main` no cambian.

Para la Fase II se añadirían a `CifradoService` el **alta y autenticación
de varios usuarios** (volver a introducir un método de registro, que en la
Fase I se eliminó a propósito) y el **compartir archivos** (entregar la
clave AES `k_fi` cifrada con la clave pública del destinatario). Las dos
interfaces lo reutilizarían.