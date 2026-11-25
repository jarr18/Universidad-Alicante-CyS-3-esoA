package service;

import crypto.AesUtil;
import crypto.HashUtil;
import crypto.RsaUtil;
import model.ArchivoCifrado;
import model.Usuario;
import storage.ArchivoRepository;
import storage.UsuarioRepository;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

/**
 * Logica de la aplicacion (login, cifrado y descifrado de archivos),
 * independiente de la interfaz. La usan tanto la consola (Main) como la
 * interfaz grafica (gui.VentanaPrincipal).
 *
 * Fase I: existe un unico usuario con su password (no hay modulo de
 * registro; el alta de usuarios es cosa de la Fase II). El usuario se crea
 * automaticamente la primera vez que arranca el programa.
 *
 * Los errores "esperables" (password incorrecto, archivo inexistente...)
 * se lanzan como IllegalArgumentException / IllegalStateException con un
 * mensaje listo para mostrar al usuario.
 */
public class CifradoService {

    /** Credenciales del unico usuario de la Fase I (cambiar aqui si se desea otro password). */
    public static final String USUARIO = "usuario";
    public static final String PASSWORD_INICIAL = "clave123";

    /** Resultado de cifrar un archivo: id del registro y ruta del .enc creado. */
    public record ResultadoCifrado(int id, Path rutaEnc) {}

    private final UsuarioRepository usuarioRepo = new UsuarioRepository();
    private final ArchivoRepository archivoRepo = new ArchivoRepository();

    // Estado de la sesion actual
    private Usuario usuarioActual = null;
    private java.security.PrivateKey clavePrivadaActual = null;

    public CifradoService() {
        crearUsuarioUnicoSiNoExiste();
    }

    // ---------------------------------------------------------------
    // Sesion
    // ---------------------------------------------------------------

    /**
     * Primera ejecucion: genera (Ku, ku) para el unico usuario y protege ku con
     * AES-128 (clave = SHA3-256(password)). Si ya existe en data/usuarios.txt no hace nada.
     */
    private void crearUsuarioUnicoSiNoExiste() {
        if (usuarioRepo.existe(USUARIO)) return;

        KeyPair par = RsaUtil.generarParClaves();
        SecretKey claveAesPassword = AesUtil.claveDesdeBytes(HashUtil.derivarClaveAes128(PASSWORD_INICIAL));

        byte[] iv = AesUtil.generarIv();
        byte[] clavePrivadaProtegida = AesUtil.cifrar(par.getPrivate().getEncoded(), claveAesPassword, iv);

        usuarioRepo.guardar(new Usuario(USUARIO, par.getPublic().getEncoded(), iv, clavePrivadaProtegida));
    }

    /** Login: si ku se descifra correctamente con SHA3-256(password), el password es correcto. */
    public void iniciarSesion(String nombre, String password) {
        nombre = nombre == null ? "" : nombre.trim();
        Usuario u = usuarioRepo.buscarPorNombre(nombre)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        SecretKey claveAesPassword = AesUtil.claveDesdeBytes(HashUtil.derivarClaveAes128(password == null ? "" : password));
        try {
            byte[] clavePrivadaBytes = AesUtil.descifrar(
                    u.getClavePrivadaProtegida(), claveAesPassword, u.getIvClavePrivada());
            clavePrivadaActual = RsaUtil.privadaDesdeBytes(clavePrivadaBytes);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Password incorrecto");
        }
        usuarioActual = u;
    }

    public void cerrarSesion() {
        usuarioActual = null;
        clavePrivadaActual = null;
    }

    public boolean haySesion() {
        return usuarioActual != null && clavePrivadaActual != null;
    }

    public String getNombreUsuario() {
        return usuarioActual == null ? null : usuarioActual.getNombreUsuario();
    }

    // ---------------------------------------------------------------
    // Archivos
    // ---------------------------------------------------------------

    public List<ArchivoCifrado> listar() {
        requiereSesion();
        return archivoRepo.listarPorUsuario(usuarioActual.getNombreUsuario());
    }

    /**
     * Cifra el archivo: escribe c_i en un .enc junto al original, registra
     * E_{Ku}^{RSA}(k_fi) y elimina el original.
     */
    public ResultadoCifrado cifrar(Path ruta) throws IOException {
        requiereSesion();
        if (!Files.isRegularFile(ruta)) {
            throw new IllegalArgumentException("El archivo no existe");
        }
        String nombreCompleto = ruta.getFileName().toString();
        if (nombreCompleto.endsWith(ArchivoRepository.EXTENSION_CIFRADO)) {
            throw new IllegalArgumentException("Ese archivo ya parece estar cifrado (" + ArchivoRepository.EXTENSION_CIFRADO + ")");
        }

        byte[] contenido = Files.readAllBytes(ruta);
        String extension = obtenerExtension(nombreCompleto);

        // k_fi (AES-128) y c_i = E^AES_{k_fi}(f_i)
        SecretKey claveArchivo = AesUtil.generarClave();
        byte[] iv = AesUtil.generarIv();
        byte[] contenidoCifrado = AesUtil.cifrar(contenido, claveArchivo, iv);

        // E_{Ku}^{RSA}(k_fi)
        PublicKey publica = RsaUtil.publicaDesdeBytes(usuarioActual.getClavePublica());
        byte[] claveArchivoProtegida = RsaUtil.cifrarConPublica(claveArchivo.getEncoded(), publica);

        Path rutaEnc = rutaEncLibre(ruta);
        Files.write(rutaEnc, contenidoCifrado);

        int id;
        try {
            id = archivoRepo.guardar(new ArchivoCifrado(
                    0, usuarioActual.getNombreUsuario(), nombreCompleto, extension,
                    iv, claveArchivoProtegida, rutaEnc.toString()));
        } catch (RuntimeException e) {
            Files.deleteIfExists(rutaEnc);   // no dejar un .enc sin clave registrada
            throw e;
        }

        // Solo cuando el .enc y su clave estan guardados se elimina el original
        Files.delete(ruta);
        return new ResultadoCifrado(id, rutaEnc);
    }

    /**
     * Descifra el archivo con ese id, lo restaura en carpetaDestino (o en la
     * carpeta del .enc si es null) y ELIMINA el .enc y la clave protegida.
     * Devuelve la ruta del archivo restaurado.
     */
    public Path descifrar(int id, Path carpetaDestino) throws IOException {
        requiereSesion();
        ArchivoCifrado archivo = archivoRepo.buscarPorId(id)
                .filter(a -> a.getNombreUsuarioPropietario().equals(usuarioActual.getNombreUsuario()))
                .orElseThrow(() -> new IllegalArgumentException("Archivo no encontrado en tu lista"));

        Path rutaEnc = Path.of(archivo.getRutaCifrado());
        if (!Files.isRegularFile(rutaEnc)) {
            throw new IllegalStateException("No se encuentra el fichero cifrado: " + rutaEnc);
        }

        Path carpeta = (carpetaDestino != null) ? carpetaDestino : rutaEnc.toAbsolutePath().getParent();
        Files.createDirectories(carpeta);
        Path destino = carpeta.resolve(archivo.getNombreOriginal());
        if (Files.exists(destino)) {
            throw new IllegalStateException("Ya existe " + destino + "; no se sobrescribe");
        }

        // k_fi = D^RSA_{ku}(E^RSA_{Ku}(k_fi)),  f_i = D^AES_{k_fi}(c_i)
        byte[] claveArchivoBytes = RsaUtil.descifrarConPrivada(
                archivo.getClaveArchivoProtegida(), clavePrivadaActual);
        SecretKey claveArchivo = AesUtil.claveDesdeBytes(claveArchivoBytes);
        byte[] contenido = AesUtil.descifrar(Files.readAllBytes(rutaEnc), claveArchivo, archivo.getIvArchivo());
        Files.write(destino, contenido);

        // Un solo uso: sin E_{Ku}^{RSA}(k_fi) el cifrado ya no se puede revertir
        Files.delete(rutaEnc);
        archivoRepo.eliminar(id);
        return destino;
    }

    // ---------------------------------------------------------------
    // Auxiliares
    // ---------------------------------------------------------------

    private void requiereSesion() {
        if (!haySesion()) {
            throw new IllegalStateException("Debes iniciar sesion primero");
        }
    }

    private static String obtenerExtension(String nombreArchivo) {
        int i = nombreArchivo.lastIndexOf('.');
        return (i >= 0) ? nombreArchivo.substring(i + 1) : "";
    }

    /** Misma carpeta y nombre base que el original, con extension .enc (sin pisar nada existente). */
    private static Path rutaEncLibre(Path original) {
        String nombre = original.getFileName().toString();
        int punto = nombre.lastIndexOf('.');
        String base = (punto > 0) ? nombre.substring(0, punto) : nombre;
        Path carpeta = original.toAbsolutePath().getParent();
        Path candidato = carpeta.resolve(base + ArchivoRepository.EXTENSION_CIFRADO);
        int n = 2;
        while (Files.exists(candidato)) {   // p.ej. foto.jpg y foto.png -> foto.enc y foto_2.enc
            candidato = carpeta.resolve(base + "_" + n++ + ArchivoRepository.EXTENSION_CIFRADO);
        }
        return candidato;
    }
}
