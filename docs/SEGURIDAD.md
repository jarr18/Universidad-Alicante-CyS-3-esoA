# Capítulo de seguridad (Fase II)

## 1. Notación (léase primero)

Todas las operaciones se escriben con **una sola llamada a función por línea**.
El **algoritmo** va en **superíndice** y la **clave** en **subíndice**.

| Símbolo | Significado |
|---|---|
| E<sup>A</sup><sub>k</sub>(m) | Cifrar el mensaje *m* con el algoritmo *A* usando la clave *k* |
| D<sup>A</sup><sub>k</sub>(c) | Descifrar el criptograma *c* con el algoritmo *A* usando la clave *k* |
| H<sup>SHA3</sup>(m) | Hash SHA3-256 de *m* (256 bits) |
| KDF<sup>SHA3</sup><sub>s,c</sub>(p) | PBKDF propio basado en SHA3-256 con sal *s* y *c* iteraciones, aplicado a la contraseña *p* |
| M<sup>HMAC</sup><sub>k</sub>(m) | Firma HMAC-SHA256 de *m* con la clave *k* (se usa en el JWT) |
| T<sup>TOTP</sup><sub>σ</sub>(t) | Código de 6 dígitos TOTP (RFC 6238) para el secreto σ en el instante *t* |
| a ‖ b | Concatenación de *a* y *b* |
| x[0..15], x[16..31] | Primera y segunda mitad (16 bytes) de *x* |

Algoritmos usados como superíndice: **AES** = AES-128 en modo GCM (cifrado autenticado), **RSA** = RSA-2048 con relleno OAEP (SHA-256).

| Elemento | Qué es | Dónde está |
|---|---|---|
| *u* | Un usuario | Cliente y servidor |
| *p<sub>u</sub>* | Contraseña de *u* | **Solo en la cabeza del usuario**; nunca se guarda ni se envía |
| *s<sub>u</sub>* | Sal del PBKDF (16 bytes aleatorios) | Servidor (es pública) |
| *d<sub>u</sub>* | Resultado del PBKDF (32 bytes) | Solo en memoria del cliente, un instante |
| *a<sub>u</sub>* | Mitad de **a**utenticación de *d<sub>u</sub>* (16 bytes) | Se envía al servidor al hacer login |
| *e<sub>u</sub>* | Mitad de **c**ifrado de *d<sub>u</sub>* (16 bytes) | **Nunca sale del cliente** |
| *K<sub>u</sub>*, *k<sub>u</sub>* | Clave pública / privada RSA de *u* | *K<sub>u</sub>* en servidor; *k<sub>u</sub>* solo cifrada en servidor y en claro solo en memoria del cliente |
| *P<sub>u</sub>* | Clave privada protegida: E<sup>AES</sup><sub>e<sub>u</sub></sub>(*k<sub>u</sub>*) | Servidor |
| *f<sub>i</sub>* | Archivo multimedia *i* (en claro) | Solo en el equipo del usuario |
| *k<sub>fi</sub>* | Clave AES-128 aleatoria del archivo *i* (una distinta por archivo) | Solo en memoria del cliente; en el servidor solo envuelta con RSA |
| *c<sub>i</sub>* | Archivo *i* cifrado | Servidor |
| *W<sub>i</sub>* | Clave del archivo envuelta: E<sup>RSA</sup><sub>K<sub>u</sub></sub>(*k<sub>fi</sub>*) | Servidor |
| *σ<sub>u</sub>* | Secreto TOTP de *u* | Servidor (cifrado en reposo) y aplicación de autenticación |
| *k<sub>S</sub>* | Clave maestra del servidor (`servidor.key`) | Solo servidor |

## 2. Procesos

### 2.1 Alta de usuario (el cliente hace todo el trabajo criptográfico)
1. *s<sub>u</sub>* = 16 bytes aleatorios
2. *d<sub>u</sub>* = KDF<sup>SHA3</sup><sub>s<sub>u</sub>,200000</sub>(*p<sub>u</sub>*)
3. *a<sub>u</sub>* = *d<sub>u</sub>*[0..15]
4. *e<sub>u</sub>* = *d<sub>u</sub>*[16..31]
5. (*K<sub>u</sub>*, *k<sub>u</sub>*) = par de claves RSA-2048 aleatorio
6. *P<sub>u</sub>* = E<sup>AES</sup><sub>e<sub>u</sub></sub>(*k<sub>u</sub>*)
7. El cliente envía al servidor: *u*, *s<sub>u</sub>*, 200000, *a<sub>u</sub>*, *K<sub>u</sub>*, *P<sub>u</sub>*
8. El servidor genera una sal propia *z<sub>u</sub>* y guarda *v<sub>u</sub>* = H<sup>SHA3</sup>(*z<sub>u</sub>* ‖ *a<sub>u</sub>*)

El servidor **no recibe ni *p<sub>u</sub>* ni *e<sub>u</sub>***: aunque se robase toda su base de datos, no puede descifrar *k<sub>u</sub>* sin hacer fuerza bruta sobre la contraseña (con 200 000 iteraciones por intento).

### 2.2 Inicio de sesión
1. El cliente pide *s<sub>u</sub>* y las iteraciones al servidor (para usuarios inexistentes el servidor devuelve una sal falsa determinista, así no se pueden enumerar cuentas)
2. *d<sub>u</sub>* = KDF<sup>SHA3</sup><sub>s<sub>u</sub>,c</sub>(*p<sub>u</sub>*)
3. El cliente envía *a<sub>u</sub>* = *d<sub>u</sub>*[0..15]
4. El servidor calcula H<sup>SHA3</sup>(*z<sub>u</sub>* ‖ *a<sub>u</sub>*) y lo compara con *v<sub>u</sub>* en tiempo constante
5. Si *u* no tiene 2FA, el servidor devuelve un token de acceso (§3). Si lo tiene, devuelve un token **pendiente** de 5 minutos válido solo para `/api/auth/2fa`
6. El cliente descarga *P<sub>u</sub>*
7. *k<sub>u</sub>* = D<sup>AES</sup><sub>e<sub>u</sub></sub>(*P<sub>u</sub>*), que queda solo en memoria

Con 5 fallos seguidos el servidor bloquea al usuario 60 segundos.

### 2.3 Segundo factor (TOTP)
1. Configurar: el servidor genera σ<sub>u</sub> (160 bits aleatorios)
2. El servidor guarda E<sup>AES</sup><sub>k<sub>S</sub></sub>(σ<sub>u</sub>)
3. El usuario añade σ<sub>u</sub> a su aplicación (Google Authenticator, Authy…)
4. Activar: el usuario envía un código; el servidor lo acepta si coincide con T<sup>TOTP</sup><sub>σ<sub>u</sub></sub>(*t*) para *t* en la ventana ±30 s
5. Anti-repetición: solo se aceptan pasos de tiempo **mayores** que el último usado

### 2.4 Cifrar y subir un archivo *f<sub>i</sub>* (en el cliente)
1. *k<sub>fi</sub>* = 16 bytes aleatorios
2. *c<sub>i</sub>* = E<sup>AES</sup><sub>k<sub>fi</sub></sub>(*f<sub>i</sub>*), con IV aleatorio de 12 bytes distinto en cada cifrado
3. *n<sub>i</sub>* = E<sup>AES</sup><sub>k<sub>fi</sub></sub>(nombre de *f<sub>i</sub>*), porque el nombre también se cifra
4. *W<sub>i</sub>* = E<sup>RSA</sup><sub>K<sub>u</sub></sub>(*k<sub>fi</sub>*)
5. Se envía al servidor (*c<sub>i</sub>*, *n<sub>i</sub>*, *W<sub>i</sub>*)

### 2.5 Descargar y descifrar
1. *k<sub>fi</sub>* = D<sup>RSA</sup><sub>k<sub>u</sub></sub>(*W<sub>i</sub>*)
2. *f<sub>i</sub>* = D<sup>AES</sup><sub>k<sub>fi</sub></sub>(*c<sub>i</sub>*)

GCM comprueba la etiqueta de autenticación: si *c<sub>i</sub>* ha sido modificado (en el servidor o en tránsito), el descifrado **falla** en lugar de devolver datos corruptos (integridad de los archivos).

### 2.6 Compartir *f<sub>i</sub>* de *u<sub>1</sub>* a *u<sub>2</sub>* — **sin volver a cifrar el archivo**
1. *W<sub>i,1</sub>* = la clave envuelta que ya tiene *u<sub>1</sub>*
2. *k<sub>fi</sub>* = D<sup>RSA</sup><sub>k<sub>u1</sub></sub>(*W<sub>i,1</sub>*)
3. *K<sub>u2</sub>* = clave pública de *u<sub>2</sub>* (la pide al servidor)
4. *W<sub>i,2</sub>* = E<sup>RSA</sup><sub>K<sub>u2</sub></sub>(*k<sub>fi</sub>*)
5. El cliente envía *W<sub>i,2</sub>* al servidor, que lo guarda junto al permiso de *u<sub>2</sub>*

*c<sub>i</sub>* **no cambia**: la prueba automática compara el hash del archivo en el servidor antes y después de compartir. *u<sub>2</sub>* descifra con el proceso 2.5 usando su propia *k<sub>u2</sub>*.

## 3. Tokens (JWT, sin almacenar sesiones)

El servidor firma un JWT con HS256: `cabecera.payload.firma`, donde la firma es M<sup>HMAC</sup><sub>k<sub>J</sub></sub>(cabecera.payload) y *k<sub>J</sub>* = H<sup>SHA3</sup>("jwt" ‖ *k<sub>S</sub>*).

* El **payload es público** (solo está codificado en Base64url), por eso contiene únicamente: `sub` (usuario), `typ` (acceso/pendiente2fa), `iat`, `exp` (caducidad: 30 min el de acceso, 5 min el pendiente) y `jti` (identificador aleatorio). Nada secreto.
* Se rechaza cualquier token con firma incorrecta, `alg` distinto de HS256 (p. ej. `none`) o caducado.
* El cliente renueva el token solo cuando le quedan menos de 5 minutos, así la contraseña no se vuelve a usar.
* `logout` y la renovación añaden el `jti` a una lista de revocados en memoria hasta su caducidad.

## 4. Qué protege cada pieza

| Amenaza | Medida |
|---|---|
| Robo de la base de datos del servidor | Solo hay contenido cifrado, claves envueltas, *P<sub>u</sub>*, verificadores con sal y secretos TOTP cifrados |
| Servidor curioso | No ve contraseñas, ni *e<sub>u</sub>*, ni *k<sub>u</sub>*, ni *k<sub>fi</sub>*, ni nombres ni contenido |
| Fuerza bruta sobre la contraseña | Sal por usuario + 200 000 iteraciones + bloqueo tras 5 fallos |
| Interceptar la red | TLS (HTTPS) y la contraseña nunca viaja |
| Manipular un archivo cifrado | AES-GCM lo detecta |
| Robo del token | Caduca en 30 min; `logout` lo revoca; el payload no contiene datos sensibles |
| Reutilizar un código 2FA observado | Anti-repetición por paso de tiempo |
| Un usuario sin permiso pide un archivo | El servidor responde 404 (no revela si existe) |

## 5. Limitaciones conocidas

* **Revocar no es retroactivo**: si *u<sub>2</sub>* ya descargó y descifró el archivo, o guardó *k<sub>fi</sub>*, no se puede "des-compartir" lo que ya conoce. Revocar impide futuras descargas.
* **No hay recuperación de contraseña**: perder *p<sub>u</sub>* significa perder *k<sub>u</sub>* y todos los archivos del usuario (consecuencia directa de que el servidor no la conozca).
* **Metadatos visibles al servidor**: nombre de usuario, tamaño y fecha de cada archivo, y quién comparte con quién.
* **Los archivos se procesan en memoria** (límite 1 GiB por archivo en el servidor y la memoria de la JVM en el cliente).
* El certificado TLS incluido es **autofirmado** (válido para pruebas y la defensa); en producción habría que usar uno emitido por una CA.
* No se implementa firma digital de archivos (opcional en el enunciado).
