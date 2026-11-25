package cliente.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.Normalizer;
import java.util.Arrays;

/**
 * Toda la criptografia del cliente (solo JDK, sin librerias externas):
 *  - SHA3-256 y PBKDF basado en SHA3-256 (derivacion de claves desde la contrasena)
 *  - AES-128-GCM (cifrado autenticado de archivos, nombres y clave privada)
 *  - RSA-2048 OAEP (proteccion de las claves AES de cada archivo)
 */
public final class Cripto {

    public static final int ITERACIONES_DEFECTO = 200_000;
    private static final SecureRandom RND = new SecureRandom();

    private Cripto() {
    }

    public static class ErrorCripto extends RuntimeException {
        public ErrorCripto(String m, Throwable causa) {
            super(m, causa);
        }
    }

    public static byte[] aleatorio(int n) {
        byte[] b = new byte[n];
        RND.nextBytes(b);
        return b;
    }

    // ------------------------------------------------------------- hash / KDF

    public static byte[] sha3(byte[]... partes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            for (byte[] p : partes) md.update(p);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new ErrorCripto("SHA3-256 no disponible", e);
        }
    }

    /**
     * PBKDF propio basado en SHA3-256 (NO es PBKDF2):
     *   T_1 = SHA3-256(p || s)
     *   T_i = SHA3-256(T_(i-1) || s)      para i = 2..c
     * Devuelve T_c (32 bytes = 256 bits). La sal s hace distinto el resultado de cada
     * usuario y las c iteraciones encarecen cada intento de fuerza bruta.
     */
    public static byte[] pbkdfSha3(String password, byte[] sal, int iteraciones) {
        byte[] p = Normalizer.normalize(password, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
        byte[] t = sha3(p, sal);
        for (int i = 1; i < iteraciones; i++) t = sha3(t, sal);
        Arrays.fill(p, (byte) 0);
        return t;
    }

    /** Primera mitad (128 bits) del resultado: se envia al servidor para autenticarse. */
    public static byte[] mitadAutenticacion(byte[] derivada) {
        return Arrays.copyOfRange(derivada, 0, 16);
    }

    /** Segunda mitad (128 bits): protege la clave privada RSA. NO sale nunca del cliente. */
    public static byte[] mitadCifrado(byte[] derivada) {
        return Arrays.copyOfRange(derivada, 16, 32);
    }

    // ------------------------------------------------------------------- AES

    public static byte[] claveAes() {
        return aleatorio(16);
    }

    /** AES-128-GCM: devuelve IV(12) || cifrado || etiqueta(16). El IV es aleatorio en cada llamada. */
    public static byte[] aesCifrar(byte[] datos, byte[] clave16, byte[] aad) {
        try {
            byte[] iv = aleatorio(12);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clave16, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            byte[] ct = c.doFinal(datos);
            byte[] r = new byte[12 + ct.length];
            System.arraycopy(iv, 0, r, 0, 12);
            System.arraycopy(ct, 0, r, 12, ct.length);
            return r;
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("Error cifrando con AES", e);
        }
    }

    /** Falla (AEADBadTagException) si la clave es incorrecta o los datos fueron modificados. */
    public static byte[] aesDescifrar(byte[] blob, byte[] clave16, byte[] aad) {
        try {
            if (blob.length < 28) throw new GeneralSecurityException("Datos demasiado cortos");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clave16, "AES"), new GCMParameterSpec(128, blob, 0, 12));
            c.updateAAD(aad);
            return c.doFinal(blob, 12, blob.length - 12);
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("No se pudo descifrar (clave incorrecta o datos alterados)", e);
        }
    }

    // ------------------------------------------------------------------- RSA

    public static KeyPair parRsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048, RND);
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new ErrorCripto("RSA no disponible", e);
        }
    }

    private static final String RSA_OAEP = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    public static byte[] rsaCifrar(byte[] datos, PublicKey publica) {
        try {
            Cipher c = Cipher.getInstance(RSA_OAEP);
            c.init(Cipher.ENCRYPT_MODE, publica);
            return c.doFinal(datos);
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("Error cifrando con RSA", e);
        }
    }

    public static byte[] rsaDescifrar(byte[] datos, PrivateKey privada) {
        try {
            Cipher c = Cipher.getInstance(RSA_OAEP);
            c.init(Cipher.DECRYPT_MODE, privada);
            return c.doFinal(datos);
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("Error descifrando con RSA", e);
        }
    }

    public static PublicKey publicaDesde(byte[] x509) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(x509));
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("Clave publica no valida", e);
        }
    }

    public static PrivateKey privadaDesde(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new ErrorCripto("Clave privada no valida", e);
        }
    }
}
