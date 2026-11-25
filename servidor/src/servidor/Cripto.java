package servidor;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Primitivas criptograficas del servidor (solo JDK, sin librerias externas). */
final class Cripto {

    private static final SecureRandom RND = new SecureRandom();

    private Cripto() {
    }

    static byte[] aleatorio(int n) {
        byte[] b = new byte[n];
        RND.nextBytes(b);
        return b;
    }

    /** SHA3-256 de la concatenacion de las partes. */
    static byte[] sha3(byte[]... partes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            for (byte[] p : partes) md.update(p);
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA3-256 no disponible", e);
        }
    }

    static byte[] hmac(String algoritmo, byte[] clave, byte[] datos) {
        try {
            Mac mac = Mac.getInstance(algoritmo);
            mac.init(new SecretKeySpec(clave, algoritmo));
            return mac.doFinal(datos);
        } catch (Exception e) {
            throw new IllegalStateException(algoritmo + " no disponible", e);
        }
    }

    static boolean iguales(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static byte[] deB64(String s) {
        return Base64.getDecoder().decode(s);
    }

    static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] deB64u(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    /** AES-128-GCM: devuelve IV(12) || texto cifrado || etiqueta. Se usa para el secreto TOTP en reposo. */
    static byte[] cifrarGcm(byte[] datos, byte[] clave16, byte[] aad) {
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
        } catch (Exception e) {
            throw new IllegalStateException("Error cifrando", e);
        }
    }

    static byte[] descifrarGcm(byte[] blob, byte[] clave16, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clave16, "AES"), new GCMParameterSpec(128, blob, 0, 12));
            c.updateAAD(aad);
            return c.doFinal(blob, 12, blob.length - 12);
        } catch (Exception e) {
            throw new IllegalStateException("Error descifrando", e);
        }
    }
}
