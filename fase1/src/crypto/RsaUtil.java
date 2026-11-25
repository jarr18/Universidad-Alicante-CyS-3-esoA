package crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utilidades RSA.
 * Se usa para proteger la clave AES-128 de cada archivo: E^RSA_Ku(k_fi).
 */
public final class RsaUtil {

    private static final String ALGORITMO = "RSA";
    private static final String TRANSFORMACION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int TAMANO_CLAVE_BITS = 2048;

    private RsaUtil() {
    }

    /** Genera un par de claves RSA (Ku publica / ku privada) para un usuario nuevo. */
    public static KeyPair generarParClaves() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITMO);
            kpg.initialize(TAMANO_CLAVE_BITS, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generando par de claves RSA", e);
        }
    }

    public static byte[] cifrarConPublica(byte[] datos, PublicKey publica) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION);
            cipher.init(Cipher.ENCRYPT_MODE, publica);
            return cipher.doFinal(datos);
        } catch (Exception e) {
            throw new RuntimeException("Error cifrando con RSA", e);
        }
    }

    public static byte[] descifrarConPrivada(byte[] datosCifrados, PrivateKey privada) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMACION);
            cipher.init(Cipher.DECRYPT_MODE, privada);
            return cipher.doFinal(datosCifrados);
        } catch (Exception e) {
            throw new RuntimeException("Error descifrando con RSA", e);
        }
    }

    public static PublicKey publicaDesdeBytes(byte[] bytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITMO);
            return kf.generatePublic(new X509EncodedKeySpec(bytes));
        } catch (Exception e) {
            throw new RuntimeException("Error reconstruyendo clave publica RSA", e);
        }
    }

    public static PrivateKey privadaDesdeBytes(byte[] bytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITMO);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (Exception e) {
            throw new RuntimeException("Error reconstruyendo clave privada RSA", e);
        }
    }
}
