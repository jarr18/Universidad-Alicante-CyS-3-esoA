package cliente;

import cliente.crypto.Cripto;
import cliente.net.ApiClient;
import cliente.net.ApiException;
import comun.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * Logica del cliente (sin interfaz grafica): registro, login con 2FA, cifrado y subida,
 * descarga y descifrado, apertura, comparticion y revocacion.
 *
 * Reglas de seguridad que se cumplen aqui:
 *  - La contrasena nunca sale del cliente: solo viaja la mitad de autenticacion del PBKDF.
 *  - Cada archivo se cifra con AES-128 y una clave k_f nueva y aleatoria.
 *  - k_f solo se guarda envuelta con RSA: E^RSA_Ku(k_f). El servidor nunca la ve en claro.
 *  - Compartir NO reencripta el archivo: solo se re-envuelve k_f con la clave publica del destinatario.
 */
public class ClienteServicio {

    public record ArchivoInfo(String id, String nombre, String propietario, long tam, long creado,
                              boolean esPropio, String compartidoPor, List<String> compartidoCon) {
    }

    public record Descifrado(String nombre, byte[] contenido) {
    }

    private record Entrada(ArchivoInfo info, String claveEnvuelta) {
    }

    private static final byte[] AAD_ARCHIVO = "cys-archivo".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AAD_NOMBRE = "cys-nombre".getBytes(StandardCharsets.US_ASCII);
    public static final int LONGITUD_MIN_PASSWORD = 8;

    private final ApiClient api;
    private String usuario;
    private PrivateKey clavePrivada;      // ku: solo en memoria durante la sesion
    private PublicKey clavePublica;       // Ku
    private byte[] mitadCifradoPendiente; // entre el paso 1 (password) y el paso 2 (codigo 2FA)
    private final Map<String, Entrada> cache = new HashMap<>();
    private final List<Path> temporales = new ArrayList<>();

    public ClienteServicio(String urlServidor) {
        this.api = new ApiClient(urlServidor);
    }

    public String getUsuario() {
        return usuario;
    }

    public boolean haySesion() {
        return usuario != null && clavePrivada != null && api.haySesion();
    }

    private static byte[] aadClavePrivada(String usuario) {
        return ("cys-ku:" + usuario).getBytes(StandardCharsets.UTF_8);
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static byte[] deB64(String s) {
        return Base64.getDecoder().decode(s);
    }

    /** "123 456" -> "123456" (Google Authenticator muestra el codigo con un espacio). */
    static String soloDigitos(String codigo) {
        return codigo == null ? "" : codigo.replaceAll("\\D", "");
    }

    private void requiereSesion() {
        if (!haySesion()) throw new IllegalStateException("La sesion ha caducado. Vuelve a iniciar sesion.");
    }

    // --------------------------------------------------------------- cuenta

    public void registrar(String nombre, String password) {
        if (password == null || password.length() < LONGITUD_MIN_PASSWORD)
            throw new IllegalArgumentException("La contrasena debe tener al menos " + LONGITUD_MIN_PASSWORD + " caracteres");
        byte[] sal = Cripto.aleatorio(16);
        byte[] derivada = Cripto.pbkdfSha3(password, sal, Cripto.ITERACIONES_DEFECTO);
        byte[] mitadAut = Cripto.mitadAutenticacion(derivada);
        byte[] mitadCif = Cripto.mitadCifrado(derivada);
        var par = Cripto.parRsa();
        byte[] privadaProtegida = Cripto.aesCifrar(par.getPrivate().getEncoded(), mitadCif, aadClavePrivada(nombre));
        api.objeto("POST", "/api/auth/registro", Json.obj(
                "usuario", nombre, "sal", b64(sal), "iteraciones", Cripto.ITERACIONES_DEFECTO,
                "claveAutenticacion", b64(mitadAut), "clavePublica", b64(par.getPublic().getEncoded()),
                "clavePrivadaProtegida", b64(privadaProtegida)));
        Arrays.fill(derivada, (byte) 0);
        Arrays.fill(mitadCif, (byte) 0);
    }

    /** Paso 1 del login. Devuelve true si falta el segundo factor (llamar a completar2fa). */
    public boolean iniciarSesion(String nombre, String password) {
        Map<String, Object> s = api.objeto("GET", "/api/auth/sal?usuario=" + ApiClient.codificar(nombre), null);
        byte[] sal = deB64(Json.str(s, "sal"));
        int it = (int) Json.num(s, "iteraciones", Cripto.ITERACIONES_DEFECTO);
        byte[] derivada = Cripto.pbkdfSha3(password, sal, it);
        byte[] mitadCif = Cripto.mitadCifrado(derivada);
        Map<String, Object> r = api.objeto("POST", "/api/auth/login", Json.obj(
                "usuario", nombre, "claveAutenticacion", b64(Cripto.mitadAutenticacion(derivada))));
        Arrays.fill(derivada, (byte) 0);
        api.setToken(Json.str(r, "token"), Json.num(r, "expiraEn", 1800));
        usuario = nombre;
        if (Json.bool(r, "requiere2fa")) {
            mitadCifradoPendiente = mitadCif;
            return true;
        }
        cargarClaves(mitadCif);
        return false;
    }

    /** Paso 2 del login (solo con 2FA activado). */
    public void completar2fa(String codigo) {
        if (mitadCifradoPendiente == null) throw new IllegalStateException("No hay un inicio de sesion pendiente");
        Map<String, Object> r = api.objeto("POST", "/api/auth/2fa", Json.obj("codigo", soloDigitos(codigo)));
        api.setToken(Json.str(r, "token"), Json.num(r, "expiraEn", 1800));
        byte[] m = mitadCifradoPendiente;
        mitadCifradoPendiente = null;
        cargarClaves(m);
    }

    private void cargarClaves(byte[] mitadCif) {
        Map<String, Object> yo = api.objeto("GET", "/api/yo", null);
        try {
            byte[] priv = Cripto.aesDescifrar(deB64(Json.str(yo, "clavePrivadaProtegida")), mitadCif, aadClavePrivada(usuario));
            clavePrivada = Cripto.privadaDesde(priv);
            Arrays.fill(priv, (byte) 0);
            clavePublica = Cripto.publicaDesde(deB64(Json.str(yo, "clavePublica")));
        } finally {
            Arrays.fill(mitadCif, (byte) 0);
        }
    }

    public void cerrarSesion() {
        try {
            if (api.haySesion()) api.objeto("POST", "/api/auth/logout", null);
        } catch (RuntimeException ignorada) {
            // si el servidor no responde, la sesion se cierra igualmente en local
        }
        api.olvidarToken();
        clavePrivada = null;
        clavePublica = null;
        usuario = null;
        if (mitadCifradoPendiente != null) Arrays.fill(mitadCifradoPendiente, (byte) 0);
        mitadCifradoPendiente = null;
        cache.clear();
        limpiarTemporales();
    }

    // ------------------------------------------------------------------ 2FA

    public boolean dobleFactorActivo() {
        requiereSesion();
        return Json.bool(api.objeto("GET", "/api/yo", null), "dobleFactor");
    }

    /** Devuelve {secreto, uri}. El 2FA no queda activo hasta confirmar con un codigo valido. */
    public String[] configurar2fa() {
        requiereSesion();
        Map<String, Object> r = api.objeto("POST", "/api/2fa/configurar", null);
        return new String[]{Json.str(r, "secreto"), Json.str(r, "uri")};
    }

    public void activar2fa(String codigo) {
        requiereSesion();
        api.objeto("POST", "/api/2fa/activar", Json.obj("codigo", soloDigitos(codigo)));
    }

    public void desactivar2fa(String codigo) {
        requiereSesion();
        api.objeto("POST", "/api/2fa/desactivar", Json.obj("codigo", soloDigitos(codigo)));
    }

    // -------------------------------------------------------------- archivos

    public List<ArchivoInfo> listar() {
        requiereSesion();
        List<ArchivoInfo> res = new ArrayList<>();
        cache.clear();
        for (Object o : api.lista("GET", "/api/archivos")) {
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
            String id = Json.str(m, "id");
            String nombre;
            try {
                byte[] kf = Cripto.rsaDescifrar(deB64(Json.str(m, "claveEnvuelta")), clavePrivada);
                nombre = new String(Cripto.aesDescifrar(deB64(Json.str(m, "nombreCifrado")), kf, AAD_NOMBRE), StandardCharsets.UTF_8);
            } catch (RuntimeException e) {
                nombre = "(nombre no recuperable)";
            }
            List<String> con = new ArrayList<>();
            Object lc = m.get("compartidoCon");
            if (lc instanceof List<?> l) for (Object x : l) con.add(String.valueOf(x));
            ArchivoInfo info = new ArchivoInfo(id, nombre, Json.str(m, "propietario"),
                    Json.num(m, "tam", 0), Json.num(m, "creado", 0), Json.bool(m, "esPropio"), Json.str(m, "compartidoPor"), con);
            res.add(info);
            cache.put(id, new Entrada(info, Json.str(m, "claveEnvuelta")));
        }
        res.sort((a, b) -> Long.compare(b.creado(), a.creado()));
        return res;
    }

    private Entrada entrada(String id) {
        Entrada e = cache.get(id);
        if (e == null) {
            listar();
            e = cache.get(id);
        }
        if (e == null) throw new IllegalArgumentException("Archivo no encontrado");
        return e;
    }

    private byte[] claveArchivo(Entrada e) {
        return Cripto.rsaDescifrar(deB64(e.claveEnvuelta()), clavePrivada);
    }

    /** Cifra el archivo en el cliente y sube SOLO el contenido cifrado. Devuelve el id. */
    public String subir(Path ruta) throws IOException {
        requiereSesion();
        if (!Files.isRegularFile(ruta)) throw new IllegalArgumentException("No es un archivo: " + ruta);
        byte[] datos = Files.readAllBytes(ruta);
        byte[] kf = Cripto.claveAes();                                         // k_f aleatoria
        byte[] blob = Cripto.aesCifrar(datos, kf, AAD_ARCHIVO);                // c = E^AES_kf(f)
        byte[] nombreCif = Cripto.aesCifrar(ruta.getFileName().toString().getBytes(StandardCharsets.UTF_8), kf, AAD_NOMBRE);
        byte[] envuelta = Cripto.rsaCifrar(kf, clavePublica);                  // E^RSA_Ku(k_f)
        Arrays.fill(kf, (byte) 0);
        Map<String, Object> r = api.subir("/api/archivos", blob,
                Map.of("X-Nombre-Cifrado", b64(nombreCif), "X-Clave-Envuelta", b64(envuelta)));
        return Json.str(r, "id");
    }

    public Descifrado descifrar(String id) {
        requiereSesion();
        Entrada e = entrada(id);
        byte[] kf = claveArchivo(e);
        byte[] blob = api.bytes("/api/archivos/" + id + "/contenido");
        byte[] datos = Cripto.aesDescifrar(blob, kf, AAD_ARCHIVO);
        Arrays.fill(kf, (byte) 0);
        return new Descifrado(e.info().nombre(), datos);
    }

    public Path guardarEn(String id, Path carpeta) throws IOException {
        Descifrado d = descifrar(id);
        Files.createDirectories(carpeta);
        Path destino = carpeta.resolve(nombreSeguro(d.nombre()));
        for (int i = 1; Files.exists(destino); i++) {
            String n = nombreSeguro(d.nombre());
            int p = n.lastIndexOf('.');
            destino = carpeta.resolve(p > 0 ? n.substring(0, p) + " (" + i + ")" + n.substring(p) : n + " (" + i + ")");
        }
        Files.write(destino, d.contenido());
        return destino;
    }

    /** Descifra a una carpeta temporal y devuelve la ruta para abrirla con la aplicacion del sistema. */
    public Path descifrarATemporal(String id) throws IOException {
        Path dir = Files.createTempDirectory("cys-");
        temporales.add(dir);
        Path f = guardarEn(id, dir);
        f.toFile().deleteOnExit();
        dir.toFile().deleteOnExit();
        return f;
    }

    public void limpiarTemporales() {
        for (Path dir : temporales) {
            try (var s = Files.walk(dir)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            } catch (IOException ignorada) {
                // se reintenta al salir (deleteOnExit)
            }
        }
        temporales.clear();
    }

    static String nombreSeguro(String nombre) {
        String n = nombre.replace('\\', '/');
        n = n.substring(n.lastIndexOf('/') + 1).replaceAll("[:*?\"<>|\\p{Cntrl}]", "_").trim();
        return n.isEmpty() || n.equals(".") || n.equals("..") ? "archivo" : n;
    }

    // ------------------------------------------------------------ comparticion

    public List<String> usuarios() {
        requiereSesion();
        List<String> r = new ArrayList<>();
        for (Object o : api.lista("GET", "/api/usuarios")) r.add(String.valueOf(o));
        return r;
    }

    /** NO se reencripta el archivo: se descifra k_f con ku y se vuelve a envolver con Ku del destinatario. */
    public void compartir(String id, String destinatario) {
        requiereSesion();
        Entrada e = entrada(id);
        if (!e.info().esPropio()) throw new IllegalArgumentException("Solo el propietario puede compartir un archivo");
        byte[] kf = claveArchivo(e);
        Map<String, Object> pk = api.objeto("GET", "/api/usuarios/" + ApiClient.codificar(destinatario) + "/clavepublica", null);
        byte[] envuelta = Cripto.rsaCifrar(kf, Cripto.publicaDesde(deB64(Json.str(pk, "clavePublica"))));
        Arrays.fill(kf, (byte) 0);
        api.objeto("POST", "/api/archivos/" + id + "/compartir", Json.obj("usuario", destinatario, "claveEnvuelta", b64(envuelta)));
    }

    public void dejarDeCompartir(String id, String destinatario) {
        requiereSesion();
        api.objeto("DELETE", "/api/archivos/" + id + "/compartir/" + ApiClient.codificar(destinatario), null);
    }

    public void eliminar(String id) {
        requiereSesion();
        api.objeto("DELETE", "/api/archivos/" + id, null);
        cache.remove(id);
    }

    public static String mensaje(Throwable t) {
        if (t instanceof ApiException || t instanceof IllegalArgumentException || t instanceof IllegalStateException)
            return t.getMessage();
        if (t instanceof Cripto.ErrorCripto) return t.getMessage();
        return t.getClass().getSimpleName() + ": " + t.getMessage();
    }
}
