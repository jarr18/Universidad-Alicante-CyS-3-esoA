package servidor;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import comun.Json;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API REST del servicio seguro. Todas las rutas cuelgan de /api y hablan JSON,
 * salvo la subida/descarga de archivos cifrados (application/octet-stream).
 *
 * Autenticacion: JWT (Authorization: Bearer ...). El servidor no guarda sesiones.
 * La contrasena NUNCA viaja: el cliente envia solo una mitad (128 bits) del resultado
 * del PBKDF; la otra mitad, que protege la clave privada, no sale del cliente.
 */
final class Api implements HttpHandler {

    // ------------------------------------------------------------ constantes
    static final int TTL_ACCESO_S = 30 * 60;
    static final int TTL_PENDIENTE_S = 5 * 60;
    static final int ITERACIONES_DEFECTO = 200_000;
    static final int ITERACIONES_MIN = 100_000;
    static final int ITERACIONES_MAX = 5_000_000;
    static final long MAX_ARCHIVO = 1L << 30;
    static final long MAX_JSON = 1L << 20;
    static final int MAX_FALLOS = 5;
    static final long BLOQUEO_MS = 60_000;
    static final String MSG_2FA = "Codigo 2FA incorrecto. Comprueba que lo has escrito bien y que la hora de tu ordenador y la de tu movil estan sincronizadas (maximo 30 s de diferencia).";
    static final Pattern NOMBRE_USUARIO = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");

    enum Auth { NINGUNA, ACCESO, PENDIENTE_2FA }

    interface Manejador {
        void tratar(Ctx c) throws Exception;
    }

    record Ruta(String metodo, Pattern patron, Auth auth, Manejador manejador) {
    }

    static final class ApiError extends Exception {
        final int estado;

        ApiError(int estado, String mensaje) {
            super(mensaje);
            this.estado = estado;
        }
    }

    /** Contexto de una peticion. */
    static final class Ctx {
        final HttpExchange ex;
        final List<String> params = new ArrayList<>();
        String usuario;
        String jti;

        Ctx(HttpExchange ex) {
            this.ex = ex;
        }

        Map<String, String> consulta() {
            Map<String, String> m = new HashMap<>();
            String q = ex.getRequestURI().getRawQuery();
            if (q == null) return m;
            for (String par : q.split("&")) {
                int i = par.indexOf('=');
                if (i > 0) m.put(URLDecoder.decode(par.substring(0, i), StandardCharsets.UTF_8),
                        URLDecoder.decode(par.substring(i + 1), StandardCharsets.UTF_8));
            }
            return m;
        }

        byte[] cuerpo(long max) throws IOException, ApiError {
            String cl = ex.getRequestHeaders().getFirst("Content-Length");
            if (cl != null) {
                try {
                    if (Long.parseLong(cl) > max) throw new ApiError(413, "Cuerpo demasiado grande");
                } catch (NumberFormatException e) {
                    throw new ApiError(400, "Content-Length no valido");
                }
            }
            byte[] b = ex.getRequestBody().readNBytes((int) Math.min(max + 1, Integer.MAX_VALUE - 8));
            if (b.length > max) throw new ApiError(413, "Cuerpo demasiado grande");
            return b;
        }

        Map<String, Object> json() throws IOException, ApiError {
            try {
                return Json.parseObjeto(new String(cuerpo(MAX_JSON), StandardCharsets.UTF_8));
            } catch (Json.JsonException e) {
                throw new ApiError(400, "JSON no valido");
            }
        }

        void responder(int estado, Object json) throws IOException {
            enviar(estado, Json.texto(json).getBytes(StandardCharsets.UTF_8), "application/json; charset=utf-8");
        }

        void enviar(int estado, byte[] datos, String tipo) throws IOException {
            ex.getResponseHeaders().set("Content-Type", tipo);
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            ex.sendResponseHeaders(estado, datos.length == 0 ? -1 : datos.length);
            if (datos.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(datos);
                }
            }
        }
    }

    // ---------------------------------------------------------------- estado
    private final Database db;
    private final byte[] claveJwt;
    private final byte[] claveDatos;     // 16 bytes: cifra en reposo los secretos TOTP
    private final byte[] claveSal;       // sal falsa determinista para usuarios inexistentes
    private final List<Ruta> rutas = new ArrayList<>();
    private final Map<String, Long> revocados = new ConcurrentHashMap<>();   // jti -> exp (s)
    private final Map<String, long[]> intentos = new ConcurrentHashMap<>();  // usuario -> {fallos, bloqueadoHasta}

    Api(Database db, Path dirDatos) throws IOException {
        this.db = db;
        byte[] maestra = cargarSecreto(dirDatos.resolve("servidor.key"));
        this.claveJwt = Cripto.sha3("jwt".getBytes(StandardCharsets.UTF_8), maestra);
        this.claveDatos = Arrays.copyOf(Cripto.sha3("datos".getBytes(StandardCharsets.UTF_8), maestra), 16);
        this.claveSal = Cripto.sha3("sal".getBytes(StandardCharsets.UTF_8), maestra);
        registrarRutas();
    }

    private static byte[] cargarSecreto(Path f) throws IOException {
        if (Files.exists(f)) return Files.readAllBytes(f);
        byte[] s = Cripto.aleatorio(32);
        Files.write(f, s);
        try {
            Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (Exception ignorada) {
            // Windows u otros sistemas sin permisos POSIX
        }
        return s;
    }

    private void ruta(String metodo, String regex, Auth auth, Manejador m) {
        rutas.add(new Ruta(metodo, Pattern.compile("^" + regex + "$"), auth, m));
    }

    // --------------------------------------------------------------- router
    @Override
    public void handle(HttpExchange ex) throws IOException {
        Ctx c = new Ctx(ex);
        try {
            String path = ex.getRequestURI().getPath();
            boolean existePath = false;
            for (Ruta r : rutas) {
                Matcher m = r.patron().matcher(path);
                if (!m.matches()) continue;
                existePath = true;
                if (!r.metodo().equals(ex.getRequestMethod())) continue;
                for (int i = 1; i <= m.groupCount(); i++) c.params.add(URLDecoder.decode(m.group(i), StandardCharsets.UTF_8));
                autenticar(c, r.auth());
                r.manejador().tratar(c);
                return;
            }
            throw existePath ? new ApiError(405, "Metodo no permitido") : new ApiError(404, "Ruta no encontrada");
        } catch (ApiError e) {
            c.responder(e.estado, Json.obj("error", e.getMessage()));
        } catch (Exception e) {
            System.err.println("[ERROR] " + ex.getRequestMethod() + " " + ex.getRequestURI().getPath() + ": " + e);
            c.responder(500, Json.obj("error", "Error interno del servidor"));
        } finally {
            ex.close();
        }
    }

    private void autenticar(Ctx c, Auth requerida) throws ApiError {
        if (requerida == Auth.NINGUNA) return;
        String h = c.ex.getRequestHeaders().getFirst("Authorization");
        if (h == null || !h.startsWith("Bearer ")) throw new ApiError(401, "Falta el token de acceso");
        Map<String, Object> claims;
        try {
            claims = Jwt.verificar(h.substring(7).trim(), claveJwt);
        } catch (Jwt.TokenInvalido e) {
            throw new ApiError(401, e.getMessage());
        }
        String tipo = Json.str(claims, "typ");
        if (!(requerida == Auth.ACCESO ? "acceso" : "pendiente2fa").equals(tipo)) throw new ApiError(401, "Tipo de token incorrecto");
        String jti = Json.str(claims, "jti");
        purgarRevocados();
        if (jti == null || revocados.containsKey(jti)) throw new ApiError(401, "Token revocado");
        String sub = Json.str(claims, "sub");
        if (sub == null || db.usuario(sub) == null) throw new ApiError(401, "Usuario desconocido");
        c.usuario = sub;
        c.jti = jti;
    }

    private void purgarRevocados() {
        long ahora = System.currentTimeMillis() / 1000;
        revocados.values().removeIf(exp -> exp <= ahora);
    }

    private String crearToken(String usuario, String tipo, int ttl) {
        long ahora = System.currentTimeMillis() / 1000;
        return Jwt.crear(Json.obj("sub", usuario, "typ", tipo, "iat", ahora, "exp", ahora + ttl,
                "jti", Cripto.b64u(Cripto.aleatorio(12))), claveJwt);
    }

    private void revocar(Ctx c) {
        revocados.put(c.jti, System.currentTimeMillis() / 1000 + TTL_ACCESO_S + 60);
    }

    // ------------------------------------------------------ anti fuerza bruta
    private void comprobarBloqueo(String usuario) throws ApiError {
        long[] i = intentos.get(usuario);
        if (i != null && i[1] > System.currentTimeMillis()) throw new ApiError(429, "Demasiados intentos. Espera un minuto.");
    }

    private void registrarFallo(String usuario) {
        long[] i = intentos.computeIfAbsent(usuario, k -> new long[2]);
        synchronized (i) {
            if (++i[0] >= MAX_FALLOS) {
                i[0] = 0;
                i[1] = System.currentTimeMillis() + BLOQUEO_MS;
            }
        }
    }

    // --------------------------------------------------------------- rutas
    private void registrarRutas() {
        ruta("GET", "/api/auth/sal", Auth.NINGUNA, this::sal);
        ruta("POST", "/api/auth/registro", Auth.NINGUNA, this::registro);
        ruta("POST", "/api/auth/login", Auth.NINGUNA, this::login);
        ruta("POST", "/api/auth/2fa", Auth.PENDIENTE_2FA, this::login2fa);
        ruta("POST", "/api/auth/renovar", Auth.ACCESO, this::renovar);
        ruta("POST", "/api/auth/logout", Auth.ACCESO, this::logout);
        ruta("GET", "/api/yo", Auth.ACCESO, this::yo);
        ruta("POST", "/api/2fa/configurar", Auth.ACCESO, this::configurar2fa);
        ruta("POST", "/api/2fa/activar", Auth.ACCESO, this::activar2fa);
        ruta("POST", "/api/2fa/desactivar", Auth.ACCESO, this::desactivar2fa);
        ruta("GET", "/api/usuarios", Auth.ACCESO, this::listarUsuarios);
        ruta("GET", "/api/usuarios/([^/]+)/clavepublica", Auth.ACCESO, this::clavePublica);
        ruta("GET", "/api/archivos", Auth.ACCESO, this::listarArchivos);
        ruta("POST", "/api/archivos", Auth.ACCESO, this::subirArchivo);
        ruta("GET", "/api/archivos/([0-9a-f]{32})/contenido", Auth.ACCESO, this::descargarArchivo);
        ruta("DELETE", "/api/archivos/([0-9a-f]{32})", Auth.ACCESO, this::borrarArchivo);
        ruta("POST", "/api/archivos/([0-9a-f]{32})/compartir", Auth.ACCESO, this::compartir);
        ruta("DELETE", "/api/archivos/([0-9a-f]{32})/compartir/([^/]+)", Auth.ACCESO, this::dejarDeCompartir);
    }

    private static String ok(Map<String, Object> m, String k) throws ApiError {
        String v = Json.str(m, k);
        if (v == null || v.isEmpty()) throw new ApiError(400, "Falta el campo '" + k + "'");
        return v;
    }

    private static byte[] b64(String v, String campo, int min, int max) throws ApiError {
        try {
            byte[] b = Cripto.deB64(v);
            if (b.length < min || b.length > max) throw new ApiError(400, "Longitud incorrecta en '" + campo + "'");
            return b;
        } catch (IllegalArgumentException e) {
            throw new ApiError(400, "Base64 no valido en '" + campo + "'");
        }
    }

    // --- autenticacion ------------------------------------------------------

    private void sal(Ctx c) throws Exception {
        String n = c.consulta().get("usuario");
        if (n == null || !NOMBRE_USUARIO.matcher(n).matches()) throw new ApiError(400, "Nombre de usuario no valido");
        Database.Usuario u = db.usuario(n);
        if (u != null) {
            c.responder(200, Json.obj("sal", u.salt, "iteraciones", u.iteraciones));
        } else {
            // Respuesta indistinguible para usuarios inexistentes (evita enumerar cuentas)
            byte[] falsa = Arrays.copyOf(Cripto.hmac("HmacSHA256", claveSal, n.getBytes(StandardCharsets.UTF_8)), 16);
            c.responder(200, Json.obj("sal", Cripto.b64(falsa), "iteraciones", ITERACIONES_DEFECTO));
        }
    }

    private void registro(Ctx c) throws Exception {
        Map<String, Object> b = c.json();
        String nombre = ok(b, "usuario");
        if (!NOMBRE_USUARIO.matcher(nombre).matches())
            throw new ApiError(400, "El usuario debe tener 3-32 caracteres (letras, numeros, . _ -)");
        byte[] salt = b64(ok(b, "sal"), "sal", 16, 64);
        long it = Json.num(b, "iteraciones", 0);
        if (it < ITERACIONES_MIN || it > ITERACIONES_MAX) throw new ApiError(400, "Numero de iteraciones fuera de rango");
        byte[] auth = b64(ok(b, "claveAutenticacion"), "claveAutenticacion", 16, 16);
        byte[] pub = b64(ok(b, "clavePublica"), "clavePublica", 200, 1024);
        try {
            RSAPublicKey k = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
            if (k.getModulus().bitLength() < 2048) throw new ApiError(400, "La clave RSA debe ser de al menos 2048 bits");
        } catch (ApiError e) {
            throw e;
        } catch (Exception e) {
            throw new ApiError(400, "Clave publica no valida");
        }
        b64(ok(b, "clavePrivadaProtegida"), "clavePrivadaProtegida", 100, 8192);

        Database.Usuario u = new Database.Usuario();
        u.nombre = nombre;
        u.salt = Cripto.b64(salt);
        u.iteraciones = (int) it;
        byte[] saltServidor = Cripto.aleatorio(16);
        u.saltServidor = Cripto.b64(saltServidor);
        u.verificador = Cripto.b64(Cripto.sha3(saltServidor, auth));
        u.clavePublica = Cripto.b64(pub);
        u.clavePrivadaProtegida = Json.str(b, "clavePrivadaProtegida");
        u.creado = System.currentTimeMillis();
        if (!db.crearUsuario(u)) throw new ApiError(409, "Ese nombre de usuario ya existe");
        c.responder(201, Json.obj("ok", true));
    }

    private void login(Ctx c) throws Exception {
        Map<String, Object> b = c.json();
        String nombre = ok(b, "usuario");
        byte[] auth = b64(ok(b, "claveAutenticacion"), "claveAutenticacion", 16, 16);
        comprobarBloqueo(nombre);
        Database.Usuario u = db.usuario(nombre);
        byte[] saltServidor = u != null ? Cripto.deB64(u.saltServidor) : new byte[16];
        byte[] calculado = Cripto.sha3(saltServidor, auth);
        byte[] guardado = u != null ? Cripto.deB64(u.verificador) : new byte[32];
        boolean correcto = Cripto.iguales(calculado, guardado) && u != null;
        if (!correcto) {
            registrarFallo(nombre);
            throw new ApiError(401, "Usuario o contrasena incorrectos");
        }
        intentos.remove(nombre);
        if (u.totpActivo) {
            c.responder(200, Json.obj("requiere2fa", true, "token", crearToken(nombre, "pendiente2fa", TTL_PENDIENTE_S),
                    "expiraEn", TTL_PENDIENTE_S));
        } else {
            c.responder(200, Json.obj("requiere2fa", false, "token", crearToken(nombre, "acceso", TTL_ACCESO_S),
                    "expiraEn", TTL_ACCESO_S));
        }
    }

    private void login2fa(Ctx c) throws Exception {
        Map<String, Object> b = c.json();
        comprobarBloqueo(c.usuario);
        Database.Usuario u = db.usuario(c.usuario);
        if (!u.totpActivo) throw new ApiError(400, "El usuario no tiene 2FA activado");
        long paso = verificarCodigo(u, Json.str(b, "codigo"));
        if (paso < 0) {
            registrarFallo(c.usuario);
            throw new ApiError(401, MSG_2FA);
        }
        intentos.remove(c.usuario);
        u.totpUltimoPaso = paso;
        db.actualizarUsuario();
        revocar(c);
        c.responder(200, Json.obj("token", crearToken(c.usuario, "acceso", TTL_ACCESO_S), "expiraEn", TTL_ACCESO_S));
    }

    private String secretoDe(Database.Usuario u) {
        return new String(Cripto.descifrarGcm(Cripto.deB64(u.totpSecretoCifrado), claveDatos,
                u.nombre.getBytes(StandardCharsets.UTF_8)), StandardCharsets.US_ASCII);
    }

    private long verificarCodigo(Database.Usuario u, String codigo) {
        if (u.totpSecretoCifrado == null || codigo == null) return -1;
        // Google Authenticator muestra "123 456": se aceptan espacios y guiones
        return Totp.verificar(secretoDe(u), codigo.replaceAll("[\\s-]", ""), u.totpUltimoPaso);
    }

    private void renovar(Ctx c) throws Exception {
        revocar(c);
        c.responder(200, Json.obj("token", crearToken(c.usuario, "acceso", TTL_ACCESO_S), "expiraEn", TTL_ACCESO_S));
    }

    private void logout(Ctx c) throws Exception {
        revocar(c);
        c.responder(200, Json.obj("ok", true));
    }

    private void yo(Ctx c) throws Exception {
        Database.Usuario u = db.usuario(c.usuario);
        c.responder(200, Json.obj("usuario", u.nombre, "clavePublica", u.clavePublica,
                "clavePrivadaProtegida", u.clavePrivadaProtegida, "dobleFactor", u.totpActivo,
                "iteraciones", u.iteraciones));
    }

    // --- 2FA ----------------------------------------------------------------

    private void configurar2fa(Ctx c) throws Exception {
        Database.Usuario u = db.usuario(c.usuario);
        if (u.totpActivo) throw new ApiError(409, "El 2FA ya esta activado");
        String secreto;
        if (u.totpSecretoCifrado != null) {
            // Ya hay un secreto pendiente de confirmar: se devuelve el MISMO para que la cuenta ya
            // anadida en la app de autenticacion siga siendo valida si el usuario vuelve a abrir el dialogo.
            secreto = secretoDe(u);
        } else {
            secreto = Totp.nuevoSecreto();
            u.totpSecretoCifrado = Cripto.b64(Cripto.cifrarGcm(secreto.getBytes(StandardCharsets.US_ASCII), claveDatos,
                    u.nombre.getBytes(StandardCharsets.UTF_8)));
            u.totpUltimoPaso = 0;
            db.actualizarUsuario();
        }
        c.responder(200, Json.obj("secreto", secreto, "uri", Totp.uri(u.nombre, secreto)));
    }

    private void activar2fa(Ctx c) throws Exception {
        Map<String, Object> b = c.json();
        Database.Usuario u = db.usuario(c.usuario);
        if (u.totpActivo) throw new ApiError(409, "El 2FA ya esta activado");
        comprobarBloqueo(c.usuario);
        long paso = verificarCodigo(u, Json.str(b, "codigo"));
        if (paso < 0) {
            registrarFallo(c.usuario);
            throw new ApiError(401, MSG_2FA);
        }
        u.totpActivo = true;
        u.totpUltimoPaso = paso;
        db.actualizarUsuario();
        c.responder(200, Json.obj("ok", true));
    }

    private void desactivar2fa(Ctx c) throws Exception {
        Map<String, Object> b = c.json();
        Database.Usuario u = db.usuario(c.usuario);
        if (!u.totpActivo) throw new ApiError(409, "El 2FA no esta activado");
        comprobarBloqueo(c.usuario);
        long paso = verificarCodigo(u, Json.str(b, "codigo"));
        if (paso < 0) {
            registrarFallo(c.usuario);
            throw new ApiError(401, MSG_2FA);
        }
        u.totpActivo = false;
        u.totpSecretoCifrado = null;
        db.actualizarUsuario();
        c.responder(200, Json.obj("ok", true));
    }

    // --- usuarios -----------------------------------------------------------

    private void listarUsuarios(Ctx c) throws Exception {
        List<Object> l = new ArrayList<>();
        for (String n : db.nombresUsuarios()) if (!n.equals(c.usuario)) l.add(n);
        c.responder(200, l);
    }

    private void clavePublica(Ctx c) throws Exception {
        Database.Usuario u = db.usuario(c.params.get(0));
        if (u == null) throw new ApiError(404, "Usuario no encontrado");
        c.responder(200, Json.obj("usuario", u.nombre, "clavePublica", u.clavePublica));
    }

    // --- archivos -----------------------------------------------------------

    private void listarArchivos(Ctx c) throws Exception {
        List<Object> l = new ArrayList<>();
        for (Database.Acceso ac : db.accesosDeUsuario(c.usuario)) {
            Database.Archivo a = db.archivo(ac.archivoId);
            if (a == null) continue;
            List<Object> con = new ArrayList<>();
            if (ac.propietario) {
                for (Database.Acceso o : db.accesosDeArchivo(a.id)) if (!o.usuario.equals(c.usuario)) con.add(o.usuario);
            }
            l.add(Json.obj("id", a.id, "nombreCifrado", a.nombreCifrado, "tam", a.tam, "creado", a.creado,
                    "propietario", a.propietario, "esPropio", ac.propietario, "claveEnvuelta", ac.claveEnvuelta,
                    "compartidoPor", ac.compartidoPor, "compartidoCon", con));
        }
        c.responder(200, l);
    }

    private void subirArchivo(Ctx c) throws Exception {
        String nombreCif = c.ex.getRequestHeaders().getFirst("X-Nombre-Cifrado");
        String claveEnv = c.ex.getRequestHeaders().getFirst("X-Clave-Envuelta");
        if (nombreCif == null || claveEnv == null) throw new ApiError(400, "Faltan las cabeceras X-Nombre-Cifrado / X-Clave-Envuelta");
        b64(nombreCif, "X-Nombre-Cifrado", 28, 1024);
        b64(claveEnv, "X-Clave-Envuelta", 128, 1024);
        byte[] blob = c.cuerpo(MAX_ARCHIVO);
        if (blob.length < 28) throw new ApiError(400, "Contenido cifrado no valido");
        Database.Archivo a = new Database.Archivo();
        a.id = HexFormat.of().formatHex(Cripto.aleatorio(16));
        a.propietario = c.usuario;
        a.nombreCifrado = nombreCif;
        a.tam = blob.length;
        a.creado = System.currentTimeMillis();
        Database.Acceso ac = new Database.Acceso();
        ac.archivoId = a.id;
        ac.usuario = c.usuario;
        ac.claveEnvuelta = claveEnv;
        ac.propietario = true;
        ac.fecha = a.creado;
        db.crearArchivo(a, blob, ac);
        c.responder(201, Json.obj("id", a.id));
    }

    private Database.Acceso accesoDe(Ctx c, String id) throws ApiError {
        Database.Acceso ac = db.acceso(id, c.usuario);
        if (ac == null) throw new ApiError(404, "Archivo no encontrado");   // 404 tambien si no tiene permiso
        return ac;
    }

    private void descargarArchivo(Ctx c) throws Exception {
        accesoDe(c, c.params.get(0));
        c.enviar(200, db.leerBlob(c.params.get(0)), "application/octet-stream");
    }

    private void borrarArchivo(Ctx c) throws Exception {
        String id = c.params.get(0);
        Database.Acceso ac = accesoDe(c, id);
        if (ac.propietario) db.borrarArchivo(id);
        else db.quitarAcceso(id, c.usuario);
        c.responder(200, Json.obj("ok", true));
    }

    private void compartir(Ctx c) throws Exception {
        String id = c.params.get(0);
        Database.Acceso mio = accesoDe(c, id);
        if (!mio.propietario) throw new ApiError(403, "Solo el propietario puede compartir el archivo");
        Map<String, Object> b = c.json();
        String dest = ok(b, "usuario");
        String clave = ok(b, "claveEnvuelta");
        b64(clave, "claveEnvuelta", 128, 1024);
        if (dest.equals(c.usuario)) throw new ApiError(400, "No puedes compartir un archivo contigo mismo");
        if (db.usuario(dest) == null) throw new ApiError(404, "El usuario destinatario no existe");
        if (db.acceso(id, dest) != null) throw new ApiError(409, "El archivo ya esta compartido con ese usuario");
        Database.Acceso nuevo = new Database.Acceso();
        nuevo.archivoId = id;
        nuevo.usuario = dest;
        nuevo.claveEnvuelta = clave;       // E^RSA_Ku_dest(k_f): el archivo NO se vuelve a cifrar
        nuevo.propietario = false;
        nuevo.compartidoPor = c.usuario;
        nuevo.fecha = System.currentTimeMillis();
        db.anadirAcceso(nuevo);
        c.responder(201, Json.obj("ok", true));
    }

    private void dejarDeCompartir(Ctx c) throws Exception {
        String id = c.params.get(0);
        Database.Acceso mio = accesoDe(c, id);
        if (!mio.propietario) throw new ApiError(403, "Solo el propietario puede revocar accesos");
        String dest = c.params.get(1);
        if (dest.equals(c.usuario) || !db.quitarAcceso(id, dest)) throw new ApiError(404, "Ese usuario no tiene acceso compartido");
        c.responder(200, Json.obj("ok", true));
    }
}
