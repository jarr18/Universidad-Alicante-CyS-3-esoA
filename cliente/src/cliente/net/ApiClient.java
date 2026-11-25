package cliente.net;

import comun.Json;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Cliente de la API REST. Guarda el token JWT y lo renueva solo cuando le quedan
 * menos de 5 minutos, de modo que la contrasena no hay que volver a usarla.
 */
public class ApiClient {

    private final String base;
    private final HttpClient http;
    private String token;
    private long caducaMs;

    public ApiClient(String urlServidor) {
        String u = urlServidor.trim();
        this.base = u.endsWith("/") ? u.substring(0, u.length() - 1) : u;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public String getBase() {
        return base;
    }

    public void setToken(String token, long expiraEnSegundos) {
        this.token = token;
        this.caducaMs = System.currentTimeMillis() + expiraEnSegundos * 1000;
    }

    public boolean haySesion() {
        return token != null && caducaMs > System.currentTimeMillis();
    }

    public void olvidarToken() {
        token = null;
    }

    public static String codificar(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------- JSON

    public Map<String, Object> objeto(String metodo, String ruta, Object cuerpo) {
        Object o = json(metodo, ruta, cuerpo);
        if (!(o instanceof Map)) throw new ApiException(0, "Respuesta inesperada del servidor");
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
        return m;
    }

    public List<Object> lista(String metodo, String ruta) {
        Object o = json(metodo, ruta, null);
        if (!(o instanceof List)) throw new ApiException(0, "Respuesta inesperada del servidor");
        @SuppressWarnings("unchecked") List<Object> l = (List<Object>) o;
        return l;
    }

    private Object json(String metodo, String ruta, Object cuerpo) {
        HttpRequest.Builder b = nueva(ruta);
        HttpRequest.BodyPublisher bp = cuerpo == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(Json.texto(cuerpo), StandardCharsets.UTF_8);
        if (cuerpo != null) b.header("Content-Type", "application/json");
        byte[] r = enviar(b.method(metodo, bp).build());
        return Json.parse(new String(r, StandardCharsets.UTF_8));
    }

    // --------------------------------------------------------------- bytes

    public byte[] bytes(String ruta) {
        return enviar(nueva(ruta).GET().build());
    }

    public Map<String, Object> subir(String ruta, byte[] datos, Map<String, String> cabeceras) {
        HttpRequest.Builder b = nueva(ruta).header("Content-Type", "application/octet-stream");
        cabeceras.forEach(b::header);
        byte[] r = enviar(b.POST(HttpRequest.BodyPublishers.ofByteArray(datos)).build());
        return Json.parseObjeto(new String(r, StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------- interno

    private HttpRequest.Builder nueva(String ruta) {
        renovarSiHaceFalta(ruta);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + ruta)).timeout(Duration.ofMinutes(10));
        if (token != null) b.header("Authorization", "Bearer " + token);
        return b;
    }

    private void renovarSiHaceFalta(String ruta) {
        if (token == null || ruta.startsWith("/api/auth/")) return;
        long restante = caducaMs - System.currentTimeMillis();
        if (restante > 0 && restante < 5 * 60_000L) {
            Map<String, Object> r = objetoSinRenovar("POST", "/api/auth/renovar");
            setToken(Json.str(r, "token"), Json.num(r, "expiraEn", 1800));
        }
    }

    private Map<String, Object> objetoSinRenovar(String metodo, String ruta) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + ruta)).timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token);
        return Json.parseObjeto(new String(enviar(b.method(metodo, HttpRequest.BodyPublishers.noBody()).build()), StandardCharsets.UTF_8));
    }

    private byte[] enviar(HttpRequest req) {
        try {
            HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() / 100 == 2) return r.body();
            String msg = "Error " + r.statusCode();
            try {
                String e = Json.str(Json.parseObjeto(new String(r.body(), StandardCharsets.UTF_8)), "error");
                if (e != null) msg = e;
            } catch (RuntimeException ignorada) {
                // el cuerpo no era JSON
            }
            throw new ApiException(r.statusCode(), msg);
        } catch (IOException e) {
            throw new ApiException(0, "No se pudo conectar con el servidor (" + base + "): " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(0, "Operacion interrumpida");
        }
    }
}
