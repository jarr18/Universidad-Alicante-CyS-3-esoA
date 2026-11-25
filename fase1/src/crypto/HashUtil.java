package crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * SHA3-256(p_u): se usa para derivar, a partir del password del usuario,
 * la clave AES-128 que protege su clave privada RSA k_u.
 *
 * SHA3-256 esta disponible nativamente desde Java 9 en el proveedor SUN
 * (no requiere ninguna libreria externa como BouncyCastle).
 */
public final class HashUtil {

    private HashUtil() {
    }

    /** Devuelve SHA3-256(password) como array de 32 bytes. */
    public static byte[] sha3_256(String texto) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            return md.digest(texto.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Error calculando SHA3-256 "
                    + "(requiere Java 9 o superior)", e);
        }
    }

    /**
     * El hash SHA3-256 produce 32 bytes (256 bits), pero AES-128 necesita
     * una clave de 16 bytes (128 bits). Se truncan los primeros 16 bytes
     * del hash, tal como sugiere el enunciado ("¿128 bits?").
     */
    public static byte[] derivarClaveAes128(String password) {
        byte[] hash = sha3_256(password);
        byte[] clave128 = new byte[16];
        System.arraycopy(hash, 0, clave128, 0, 16);
        return clave128;
    }
}
