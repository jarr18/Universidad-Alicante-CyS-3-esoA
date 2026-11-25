package servidor;

import comun.Json;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * JWT firmado con HMAC-SHA256 (HS256), sin almacenar nada en el servidor.
 * El payload es PUBLICO (solo esta en Base64url): por eso solo lleva el nombre
 * de usuario, el tipo de token, la fecha de emision/caducidad y un identificador.
 */
final class Jwt {

    static final class TokenInvalido extends Exception {
        TokenInvalido(String m) {
            super(m);
        }
    }

    private static final String CABECERA = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    private Jwt() {
    }

    static String crear(Map<String, Object> claims, byte[] clave) {
        String h = Cripto.b64u(CABECERA.getBytes(StandardCharsets.UTF_8));
        String p = Cripto.b64u(Json.texto(claims).getBytes(StandardCharsets.UTF_8));
        String firma = Cripto.b64u(Cripto.hmac("HmacSHA256", clave, (h + "." + p).getBytes(StandardCharsets.US_ASCII)));
        return h + "." + p + "." + firma;
    }

    /** Verifica firma, algoritmo y caducidad; devuelve los claims. */
    static Map<String, Object> verificar(String token, byte[] clave) throws TokenInvalido {
        try {
            String[] partes = token.split("\\.", -1);
            if (partes.length != 3) throw new TokenInvalido("Formato de token incorrecto");
            Map<String, Object> cab = Json.parseObjeto(new String(Cripto.deB64u(partes[0]), StandardCharsets.UTF_8));
            if (!"HS256".equals(Json.str(cab, "alg"))) throw new TokenInvalido("Algoritmo no admitido");
            byte[] esperada = Cripto.hmac("HmacSHA256", clave, (partes[0] + "." + partes[1]).getBytes(StandardCharsets.US_ASCII));
            if (!Cripto.iguales(esperada, Cripto.deB64u(partes[2]))) throw new TokenInvalido("Firma no valida");
            Map<String, Object> claims = Json.parseObjeto(new String(Cripto.deB64u(partes[1]), StandardCharsets.UTF_8));
            long exp = Json.num(claims, "exp", 0);
            if (exp <= System.currentTimeMillis() / 1000) throw new TokenInvalido("Token caducado");
            return claims;
        } catch (TokenInvalido e) {
            throw e;
        } catch (RuntimeException e) {
            throw new TokenInvalido("Token mal formado");
        }
    }
}
