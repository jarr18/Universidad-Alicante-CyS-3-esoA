package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Utilidades AES-128 en modo CTR (Counter mode), sin padding.
 * Se usa tanto para:
 *   - cifrar cada archivo f_i con su clave k_fi
 *   - cifrar la clave privada RSA k_u con SHA3-256(p_u) como clave
 *
 * En CTR, AES no cifra el dato directamente: cifra un contador (el
 * IV de 16 bytes hace de valor inicial de ese contador) y el resultado
 * se combina con el texto claro mediante XOR, byte a byte. Por eso no
 * hace falta padding (el archivo puede tener cualquier longitud) y el
 * cifrado/descifrado se puede paralelizar bloque a bloque.
 *
 * Requisito de seguridad de CTR: el par (clave, IV) NUNCA debe
 * reutilizarse para cifrar dos datos distintos. Como generarIv()
 * genera un IV aleatorio nuevo en cada llamada (SecureRandom, 128
 * bits de espacio), la probabilidad de colision es despreciable.
 */
public final class AesUtil {

    private static final String ALGORITMO = "AES";
    private static final String TRANSFORMACION = "AES/CTR/NoPadding";
    private static final int TAMANO_CLAVE_BITS = 128;
    public static final int TAMANO_IV_BYTES = 16;

    private AesUtil() {
    }

    /** Genera una clave AES-128 aleatoria (k_fi para un archivo). */
    public static SecretKey generarClave() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITMO);
            kg.init(TAMANO_CLAVE_BITS, new SecureRandom());
            return kg.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Error generando clave AES", e);
        }
    }

    /**
     * Genera un IV aleatorio de 16 bytes, usado en CTR como valor
     * inicial del contador. Debe ser distinto en cada cifrado.
     */
    public static byte[] generarIv() {
        byte[] iv = new byte[TAMANO_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /** Reconstruye una SecretKey AES a partir de bytes en claro (p.ej. un hash truncado a 128 bits). */
    public static SecretKey claveDesdeBytes(byte[] bytes) {
        byte[] clave16 = new byte[16];
        System.arraycopy(bytes, 0, clave16, 0, Math.min(bytes.length, 16));
        return new SecretKeySpec(clave16, ALGORITMO);
    }

    public static byte[] cifrar(byte[] datos, SecretKey clave, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION);
            cipher.init(Cipher.ENCRYPT_MODE, clave, new IvParameterSpec(iv));
            return cipher.doFinal(datos);
        } catch (Exception e) {
            throw new RuntimeException("Error cifrando con AES", e);
        }
    }

    public static byte[] descifrar(byte[] datosCifrados, SecretKey clave, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION);
            cipher.init(Cipher.DECRYPT_MODE, clave, new IvParameterSpec(iv));
            return cipher.doFinal(datosCifrados);
        } catch (Exception e) {
            throw new RuntimeException("Error descifrando con AES", e);
        }
    }
}
