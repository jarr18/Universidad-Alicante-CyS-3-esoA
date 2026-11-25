package servidor;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.Executors;

/**
 * Servidor del servicio seguro de contenidos multimedia (Fase II).
 * Uso: java -cp out/servidor servidor.ServidorMain [--puerto 8443] [--datos datos-servidor]
 *                                                  [--tls certs/servidor.p12 clave]
 */
public final class ServidorMain {

    private ServidorMain() {
    }

    public static HttpServer iniciar(Path datos, String host, int puerto, Path p12, String claveP12) throws Exception {
        Files.createDirectories(datos);
        Database db = new Database(datos);
        Api api = new Api(db, datos);
        HttpServer srv;
        if (p12 != null) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(p12)) {
                ks.load(in, claveP12.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, claveP12.toCharArray());
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            HttpsServer https = HttpsServer.create(new InetSocketAddress(host, puerto), 0);
            https.setHttpsConfigurator(new HttpsConfigurator(ctx));
            srv = https;
        } else {
            srv = HttpServer.create(new InetSocketAddress(host, puerto), 0);
        }
        srv.createContext("/api", api);
        srv.setExecutor(Executors.newFixedThreadPool(16));
        srv.start();
        return srv;
    }

    public static void main(String[] args) throws Exception {
        int puerto = 8443;
        String host = "0.0.0.0";
        Path datos = Path.of("datos-servidor");
        Path p12 = null;
        String clave = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--puerto" -> puerto = Integer.parseInt(args[++i]);
                case "--host" -> host = args[++i];
                case "--datos" -> datos = Path.of(args[++i]);
                case "--tls" -> {
                    p12 = Path.of(args[++i]);
                    clave = args[++i];
                }
                default -> {
                    System.err.println("Argumento desconocido: " + args[i]);
                    System.exit(2);
                }
            }
        }
        HttpServer srv = iniciar(datos, host, puerto, p12, clave);
        String esquema = p12 != null ? "https" : "http";
        System.out.println("=== Servidor CyS Fase II ===");
        System.out.println("Escuchando en " + esquema + "://" + host + ":" + srv.getAddress().getPort() + "/api");
        System.out.println("Datos en: " + datos.toAbsolutePath());
        if (p12 == null) System.out.println("AVISO: sin TLS. Usa --tls para cifrar el canal (ver README).");
    }
}
