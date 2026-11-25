package servidor;

import java.nio.ByteBuffer;

/** TOTP (RFC 6238): HMAC-SHA1, 6 digitos, paso de 30 s. Compatible con Google Authenticator, Authy, etc. */
final class Totp {

    static final int PASO_SEGUNDOS = 30;
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Totp() {
    }

    static String nuevoSecreto() {
        return base32(Cripto.aleatorio(20));
    }

    static String uri(String usuario, String secretoBase32) {
        return "otpauth://totp/CyS-Fase2:" + usuario + "?secret=" + secretoBase32
                + "&issuer=CyS-Fase2&algorithm=SHA1&digits=6&period=" + PASO_SEGUNDOS;
    }

    static long pasoActual() {
        return System.currentTimeMillis() / 1000 / PASO_SEGUNDOS;
    }

    static String codigo(String secretoBase32, long paso) {
        byte[] h = Cripto.hmac("HmacSHA1", deBase32(secretoBase32), ByteBuffer.allocate(8).putLong(paso).array());
        int off = h[h.length - 1] & 0x0f;
        int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16) | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
        return String.format("%06d", bin % 1_000_000);
    }

    /**
     * Comprueba el codigo en la ventana [-1, +1] pasos. Devuelve el paso aceptado
     * o -1. Solo se aceptan pasos MAYORES que el ultimo usado (anti-repeticion).
     */
    static long verificar(String secretoBase32, String codigo, long ultimoPasoUsado) {
        if (codigo == null || !codigo.matches("\\d{6}")) return -1;
        long ahora = pasoActual();
        for (long p = ahora - 1; p <= ahora + 1; p++) {
            if (p > ultimoPasoUsado && Cripto.iguales(codigo(secretoBase32, p).getBytes(), codigo.getBytes())) return p;
        }
        return -1;
    }

    static String base32(byte[] datos) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : datos) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(B32.charAt((buffer << (5 - bits)) & 31));
        return sb.toString();
    }

    static byte[] deBase32(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int buffer = 0, bits = 0;
        for (char c : s.toUpperCase().toCharArray()) {
            int v = B32.indexOf(c);
            if (v < 0) continue;
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
