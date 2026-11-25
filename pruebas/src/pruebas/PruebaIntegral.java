package pruebas;

import cliente.ClienteServicio;
import cliente.crypto.Cripto;
import cliente.net.ApiException;
import com.sun.net.httpserver.HttpServer;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Random;

/**
 * Prueba de integracion de extremo a extremo: levanta el servidor REAL en un puerto libre
 * y ejecuta clientes REALES contra la API REST. Uso: ejecutar-pruebas.bat / .sh
 */
public class PruebaIntegral {

    static int ok = 0, fallos = 0;

    static void comprobar(String nombre, boolean cond) {
        if (cond) { ok++; System.out.println("  [OK]    " + nombre); }
        else { fallos++; System.out.println("  [FALLO] " + nombre); }
    }

    interface Accion { void run() throws Exception; }

    static int estado(Accion a) {
        try { a.run(); return 200; }
        catch (ApiException e) { return e.getEstado(); }
        catch (Exception e) { return -1; }
    }

    public static void main(String[] args) throws Exception {
        Path datos = Files.createTempDirectory("cys-prueba-");
        Path trabajo = Files.createTempDirectory("cys-prueba-ficheros-");
        boolean tls = args.length >= 2;
        HttpServer srv = servidor.ServidorMain.iniciar(datos, "127.0.0.1", 0,
                tls ? Path.of(args[0]) : null, tls ? args[1] : null);
        String url = (tls ? "https" : "http") + "://127.0.0.1:" + srv.getAddress().getPort();
        System.out.println("Servidor de prueba en " + url);
        try {
            ejecutar(url, datos, trabajo);
        } finally {
            srv.stop(0);
            borrar(datos);
            borrar(trabajo);
        }
        System.out.println("\nResultado: " + ok + " correctas, " + fallos + " fallidas");
        System.exit(fallos == 0 ? 0 : 1);
    }

    static void ejecutar(String url, Path datos, Path trabajo) throws Exception {
        System.out.println("\n-- Registro y login");
        ClienteServicio alice = new ClienteServicio(url), bob = new ClienteServicio(url), eve = new ClienteServicio(url);
        alice.registrar("alice", "contrasena-de-alice");
        bob.registrar("bob", "contrasena-de-bob");
        eve.registrar("eve", "contrasena-de-eve");
        comprobar("no se puede registrar un usuario repetido", estado(() -> alice.registrar("alice", "otra-contrasena-1")) == 409);
        comprobar("contrasena corta rechazada", estado(() -> alice.registrar("zoe", "corta")) == -1);
        comprobar("login con contrasena incorrecta -> 401", estado(() -> new ClienteServicio(url).iniciarSesion("alice", "mala-contrasena")) == 401);
        comprobar("usuario inexistente -> 401 (mismo error)", estado(() -> new ClienteServicio(url).iniciarSesion("nadie", "lo-que-sea-1")) == 401);
        comprobar("login correcto sin 2FA", !alice.iniciarSesion("alice", "contrasena-de-alice") && alice.haySesion());
        bob.iniciarSesion("bob", "contrasena-de-bob");
        eve.iniciarSesion("eve", "contrasena-de-eve");

        System.out.println("\n-- Cifrado, subida y descarga");
        byte[] contenido = new byte[3_000_000];
        new Random(42).nextBytes(contenido);
        Path f = trabajo.resolve("video prueba.mp4");
        Files.write(f, contenido);
        String id = alice.subir(f);
        comprobar("subida devuelve un id", id != null && id.length() == 32);
        comprobar("el listado muestra el nombre descifrado", alice.listar().stream().anyMatch(a -> a.id().equals(id) && a.nombre().equals("video prueba.mp4") && a.esPropio()));
        comprobar("descifrado identico al original", Arrays.equals(alice.descifrar(id).contenido(), contenido));
        Path blob = Files.list(datos.resolve("blobs")).findFirst().orElseThrow();
        byte[] enServidor = Files.readAllBytes(blob);
        comprobar("el servidor guarda contenido cifrado (no contiene el original)", !contieneSecuencia(enServidor, Arrays.copyOf(contenido, 64)));
        String db = Files.readString(datos.resolve("db.json"));
        comprobar("el nombre del archivo NO aparece en claro en el servidor", !db.contains("video prueba"));
        comprobar("la contrasena NO aparece en el servidor", !db.contains("contrasena-de-alice"));
        comprobar("eve no puede ver ni descargar el archivo de alice", eve.listar().isEmpty() && estado(() -> eve.descifrar(id)) != 200);

        System.out.println("\n-- Comparticion (sin reencriptar)");
        long tamAntes = Files.size(blob);
        String huellaAntes = Arrays.toString(Cripto.sha3(enServidor));
        comprobar("bob no ve el archivo antes de compartirlo", bob.listar().isEmpty());
        alice.compartir(id, "bob");
        comprobar("bob ve el archivo compartido", bob.listar().size() == 1 && !bob.listar().get(0).esPropio());
        comprobar("bob descifra el contenido correcto", Arrays.equals(bob.descifrar(id).contenido(), contenido));
        comprobar("el blob del servidor NO cambia al compartir (no se reencripta)",
                Files.size(blob) == tamAntes && Arrays.toString(Cripto.sha3(Files.readAllBytes(blob))).equals(huellaAntes));
        comprobar("alice ve con quien comparte", alice.listar().get(0).compartidoCon().contains("bob"));
        comprobar("bob no puede compartir (no es propietario) ", estado(() -> bob.compartir(id, "eve")) != 200);
        comprobar("compartir dos veces -> 409", estado(() -> alice.compartir(id, "bob")) == 409);
        comprobar("compartir con usuario inexistente -> 404", estado(() -> alice.compartir(id, "fantasma")) == 404);
        alice.dejarDeCompartir(id, "bob");
        comprobar("revocado: bob ya no accede", bob.listar().isEmpty() && estado(() -> bob.descifrar(id)) != 200);
        alice.compartir(id, "bob");
        bob.eliminar(id);
        comprobar("bob puede quitar su acceso sin borrar el archivo", alice.listar().size() == 1);

        System.out.println("\n-- Abrir (descifrado temporal)");
        Path tmp = alice.descifrarATemporal(id);
        comprobar("archivo temporal descifrado correctamente", Arrays.equals(Files.readAllBytes(tmp), contenido));
        alice.limpiarTemporales();
        comprobar("los temporales se borran", !Files.exists(tmp));

        System.out.println("\n-- Segundo factor (TOTP)");
        String[] cfg = alice.configurar2fa();
        comprobar("se entrega secreto y URI otpauth", cfg[0].length() >= 16 && cfg[1].startsWith("otpauth://totp/"));
        comprobar("pedir configurar otra vez devuelve el MISMO secreto (la app sigue valida)", alice.configurar2fa()[0].equals(cfg[0]));
        comprobar("codigo incorrecto no activa el 2FA", estado(() -> alice.activar2fa("000000")) == 401);
        String codigo = totp(cfg[0], 0);
        alice.activar2fa(codigo);
        comprobar("2FA activado", alice.dobleFactorActivo());
        alice.cerrarSesion();
        comprobar("tras cerrar sesion no hay sesion", !alice.haySesion());
        ClienteServicio alice2 = new ClienteServicio(url);
        comprobar("con 2FA el login exige un segundo paso", alice2.iniciarSesion("alice", "contrasena-de-alice") && !alice2.haySesion());
        comprobar("codigo 2FA incorrecto -> 401", estado(() -> alice2.completar2fa("123456")) == 401);
        ClienteServicio alice3 = new ClienteServicio(url);
        alice3.iniciarSesion("alice", "contrasena-de-alice");
        comprobar("reutilizar el mismo codigo se rechaza (anti-repeticion)", estado(() -> alice3.completar2fa(codigo)) == 401);
        ClienteServicio alice4 = new ClienteServicio(url);
        alice4.iniciarSesion("alice", "contrasena-de-alice");
        String c6 = totp(cfg[0], 1);
        alice4.completar2fa(c6.substring(0, 3) + " " + c6.substring(3));   // como lo muestra Google Authenticator
        comprobar("login completo con 2FA (codigo escrito con espacio) y acceso a sus archivos", alice4.haySesion() && alice4.listar().size() == 1);

        System.out.println("\n-- Tokens JWT");
        HttpClient http = HttpClient.newHttpClient();
        comprobar("sin token -> 401", get(http, url + "/api/archivos", null) == 401);
        comprobar("token falso -> 401", get(http, url + "/api/archivos", "aaa.bbb.ccc") == 401);
        String falso = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes())
                + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"sub\":\"alice\",\"typ\":\"acceso\",\"exp\":" + (System.currentTimeMillis() / 1000 + 999) + ",\"jti\":\"x\"}").getBytes()) + ".";
        comprobar("token con alg=none -> 401", get(http, url + "/api/archivos", falso) == 401);
        alice4.cerrarSesion();
        comprobar("tras el logout, la sesion queda cerrada", !alice4.haySesion());

        System.out.println("\n-- Cifrado autenticado y borrado");
        byte[] kf = Cripto.claveAes();
        byte[] c = Cripto.aesCifrar("hola".getBytes(StandardCharsets.UTF_8), kf, new byte[0]);
        c[c.length - 1] ^= 1;
        comprobar("AES-GCM detecta un archivo modificado", estado(() -> Cripto.aesDescifrar(c, kf, new byte[0])) == -1);
        comprobar("dos cifrados del mismo texto usan IV distinto", !Arrays.equals(
                Cripto.aesCifrar(new byte[10], kf, new byte[0]), Cripto.aesCifrar(new byte[10], kf, new byte[0])));
        ClienteServicio a5 = new ClienteServicio(url);
        a5.iniciarSesion("bob", "contrasena-de-bob");
        String idB = a5.subir(f);
        a5.eliminar(idB);
        comprobar("borrar un archivo propio lo elimina del servidor", a5.listar().isEmpty());
    }

    static String totp(String secreto, int pasosDespues) throws Exception {
        Class<?> t = Class.forName("servidor.Totp");
        Method m = t.getDeclaredMethod("codigo", String.class, long.class);
        Method p = t.getDeclaredMethod("pasoActual");
        m.setAccessible(true);
        p.setAccessible(true);
        return (String) m.invoke(null, secreto, (long) p.invoke(null) + pasosDespues);
    }

    static int get(HttpClient http, String url, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        if (token != null) b.header("Authorization", "Bearer " + token);
        return http.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    static boolean contieneSecuencia(byte[] g, byte[] p) {
        outer:
        for (int i = 0; i <= g.length - p.length; i++) {
            for (int j = 0; j < p.length; j++) if (g[i + j] != p[j]) continue outer;
            return true;
        }
        return false;
    }

    static void borrar(Path dir) throws Exception {
        try (var s = Files.walk(dir)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
