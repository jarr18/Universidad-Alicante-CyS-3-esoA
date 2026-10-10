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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Scanner;

/**
 * Practica Fase I - Compresion y Seguridad
 * Version simplificada: sin base de datos, todo se guarda en ficheros
 * de texto (data/usuarios.txt y data/archivos.txt).
 *
 * Flujo implementado (ver diagrama del PDF):
 *   - Registro: se genera un par RSA (Ku, ku) para el usuario. ku se
 *     protege cifrandola con AES-128, usando como clave SHA3-256(password).
 *   - Login: se recalcula SHA3-256(password) y se intenta descifrar ku;
 *     si falla, el password es incorrecto.
 *   - Cifrado: se genera k_fi (AES-128), se cifra el archivo con k_fi y
 *     se escribe como .enc (el original se elimina). k_fi se protege con Ku (RSA).
 *   - Descifrado: se recupera k_fi con ku (RSA) y se restaura el original;
 *     el .enc y la clave protegida se eliminan (un solo uso por cifrado).
 */
public class Main {

    private static final Scanner SC = new Scanner(System.in);
    private static final UsuarioRepository usuarioRepo = new UsuarioRepository();
    private static final ArchivoRepository archivoRepo = new ArchivoRepository();

    // Estado de la sesion actual
    private static Usuario usuarioActual = null;
    private static PrivateKey clavePrivadaActual = null;

    public static void main(String[] args) {
        System.out.println("=== PRACTICA FASE I - Compresion y Seguridad (version sin BD) ===");
        System.out.println("Los datos se guardan en la carpeta 'data/' (usuarios.txt y archivos.txt).");
        boolean salir = false;
        while (!salir) {
            mostrarMenu();
            String opcion = SC.nextLine().trim();
            try {
                switch (opcion) {
                    case "1" -> registrarUsuario();
                    case "2" -> iniciarSesion();
                    case "3" -> subirArchivo();
                    case "4" -> descargarArchivo();
                    case "5" -> listarArchivos();
                    case "6" -> cerrarSesion();
                    case "0" -> salir = true;
                    default -> System.out.println("Opcion no valida.");
                }
            } catch (Exception e) {
                System.out.println("ERROR: " + e.getMessage());
            }
        }
        System.out.println("Hasta luego.");
    }

    private static void mostrarMenu() {
        System.out.println();
        System.out.println("Sesion: " + (usuarioActual != null ? usuarioActual.getNombreUsuario() : "(no autenticado)"));
        System.out.println("1. Registrar usuario");
        System.out.println("2. Iniciar sesion");
        System.out.println("3. Cifrar archivo (se reemplaza por un .enc)");
        System.out.println("4. Descifrar archivo (restaura el original)");
        System.out.println("5. Listar mis archivos cifrados");
        System.out.println("6. Cerrar sesion");
        System.out.println("0. Salir");
        System.out.print("Elige una opcion: ");
    }

    // ---------------------------------------------------------------
    // 1. Registro de usuario
    // ---------------------------------------------------------------
    private static void registrarUsuario() {
        System.out.print("Nombre de usuario: ");
        String nombre = SC.nextLine().trim();
        if (usuarioRepo.existe(nombre)) {
            System.out.println("Ese usuario ya existe.");
            return;
        }
        System.out.print("Password: ");
        String password = SC.nextLine();

        // Generar par de claves RSA: Ku (publica), ku (privada)
        KeyPair par = RsaUtil.generarParClaves();
        byte[] clavePublicaBytes = par.getPublic().getEncoded();
        byte[] clavePrivadaBytes = par.getPrivate().getEncoded();

        // Derivar clave AES-128 = SHA3-256(password) truncada a 128 bits
        SecretKey claveAesPassword = AesUtil.claveDesdeBytes(HashUtil.derivarClaveAes128(password));

        // Proteger la clave privada: E^AES_{SHA3-256(pu)}(ku)
        byte[] iv = AesUtil.generarIv();
        byte[] clavePrivadaProtegida = AesUtil.cifrar(clavePrivadaBytes, claveAesPassword, iv);

        Usuario u = new Usuario(nombre, clavePublicaBytes, iv, clavePrivadaProtegida);
        usuarioRepo.guardar(u);

        System.out.println("Usuario '" + nombre + "' registrado correctamente.");
        System.out.println("Se genero su par de claves RSA; la clave privada quedo protegida con AES-128 (clave = SHA3-256(password)).");
    }

    // ---------------------------------------------------------------
    // 2. Login
    // ---------------------------------------------------------------
    private static void iniciarSesion() {
        System.out.print("Nombre de usuario: ");
        String nombre = SC.nextLine().trim();
        System.out.print("Password: ");
        String password = SC.nextLine();

        Usuario u = usuarioRepo.buscarPorNombre(nombre)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        SecretKey claveAesPassword = AesUtil.claveDesdeBytes(HashUtil.derivarClaveAes128(password));
        try {
            byte[] clavePrivadaBytes = AesUtil.descifrar(
                    u.getClavePrivadaProtegida(), claveAesPassword, u.getIvClavePrivada());
            clavePrivadaActual = RsaUtil.privadaDesdeBytes(clavePrivadaBytes);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Password incorrecto");
        }

        usuarioActual = u;
        System.out.println("Sesion iniciada como '" + nombre + "'.");
    }

    // ---------------------------------------------------------------
    // 3. Cifrar archivo
    //    El original se SUSTITUYE por un fichero .enc en la misma carpeta.
    // ---------------------------------------------------------------
    private static void subirArchivo() throws IOException {
        requiereSesion();
        System.out.print("Ruta del archivo a cifrar: ");
        Path ruta = Path.of(SC.nextLine().trim());
        if (!Files.isRegularFile(ruta)) {
            System.out.println("El archivo no existe.");
            return;
        }
        String nombreCompleto = ruta.getFileName().toString();
        if (nombreCompleto.endsWith(ArchivoRepository.EXTENSION_CIFRADO)) {
            System.out.println("Ese archivo ya parece estar cifrado (" + ArchivoRepository.EXTENSION_CIFRADO + ").");
            return;
        }

        byte[] contenido = Files.readAllBytes(ruta);
        String extension = obtenerExtension(nombreCompleto);

        // Generar clave de archivo k_fi (AES-128) y cifrar f_i
        SecretKey claveArchivo = AesUtil.generarClave();
        byte[] iv = AesUtil.generarIv();
        byte[] contenidoCifrado = AesUtil.cifrar(contenido, claveArchivo, iv);

        // Proteger k_fi con la clave publica RSA del usuario: E_{Ku}^{RSA}(k_fi)
        PublicKey publica = RsaUtil.publicaDesdeBytes(usuarioActual.getClavePublica());
        byte[] claveArchivoProtegida = RsaUtil.cifrarConPublica(claveArchivo.getEncoded(), publica);

        // c_i se escribe en un fichero .enc junto al original (nueva extension)
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
        System.out.println("Archivo cifrado con id=" + id + ".");
        System.out.println("  " + ruta.getFileName() + "  ->  " + rutaEnc.getFileName());
        System.out.println("  El original ha sido eliminado; solo existe la version cifrada.");
    }

    // ---------------------------------------------------------------
    // 4. Descifrar archivo
    //    Restaura el original y ELIMINA el .enc y su clave protegida:
    //    para volver a descifrarlo hay que volver a cifrarlo antes.
    // ---------------------------------------------------------------
    private static void descargarArchivo() throws IOException {
        requiereSesion();
        listarArchivos();
        System.out.print("Id del archivo a descifrar: ");
        int id = Integer.parseInt(SC.nextLine().trim());

        ArchivoCifrado archivo = archivoRepo.buscarPorId(id)
                .filter(a -> a.getNombreUsuarioPropietario().equals(usuarioActual.getNombreUsuario()))
                .orElseThrow(() -> new IllegalArgumentException("Archivo no encontrado en tu lista"));

        Path rutaEnc = Path.of(archivo.getRutaCifrado());
        if (!Files.isRegularFile(rutaEnc)) {
            throw new IllegalStateException("No se encuentra el fichero cifrado: " + rutaEnc);
        }

        System.out.print("Carpeta de destino (Enter = " + rutaEnc.toAbsolutePath().getParent() + "): ");
        String entrada = SC.nextLine().trim();
        Path carpeta = entrada.isEmpty() ? rutaEnc.toAbsolutePath().getParent() : Path.of(entrada);
        Files.createDirectories(carpeta);
        Path destino = carpeta.resolve(archivo.getNombreOriginal());
        if (Files.exists(destino)) {
            throw new IllegalStateException("Ya existe " + destino + "; no se sobrescribe.");
        }

        // Recuperar k_fi descifrando con la clave privada del usuario
        byte[] claveArchivoBytes = RsaUtil.descifrarConPrivada(
                archivo.getClaveArchivoProtegida(), clavePrivadaActual);
        SecretKey claveArchivo = AesUtil.claveDesdeBytes(claveArchivoBytes);

        // Descifrar el contenido del archivo con k_fi
        byte[] contenido = AesUtil.descifrar(Files.readAllBytes(rutaEnc), claveArchivo, archivo.getIvArchivo());
        Files.write(destino, contenido);

        // Una vez restaurado, se elimina el .enc y se borra la clave protegida:
        // sin E_{Ku}^{RSA}(k_fi) el cifrado ya no se puede revertir.
        Files.delete(rutaEnc);
        archivoRepo.eliminar(id);
        System.out.println("Archivo descifrado en: " + destino);
        System.out.println("  El .enc y su clave se han eliminado. Para volver a descifrarlo hay que cifrarlo de nuevo.");
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

    // ---------------------------------------------------------------
    // 5. Listar archivos
    // ---------------------------------------------------------------
    private static void listarArchivos() {
        requiereSesion();
        List<ArchivoCifrado> archivos = archivoRepo.listarPorUsuario(usuarioActual.getNombreUsuario());
        if (archivos.isEmpty()) {
            System.out.println("No tienes archivos cifrados.");
            return;
        }
        System.out.println("Tus archivos cifrados:");
        for (ArchivoCifrado a : archivos) {
            System.out.printf("  id=%d  %s  (%s)%n", a.getId(), a.getNombreOriginal(), a.getRutaCifrado());
        }
    }

    // ---------------------------------------------------------------
    // 6. Cerrar sesion
    // ---------------------------------------------------------------
    private static void cerrarSesion() {
        usuarioActual = null;
        clavePrivadaActual = null;
        System.out.println("Sesion cerrada.");
    }

    private static void requiereSesion() {
        if (usuarioActual == null || clavePrivadaActual == null) {
            throw new IllegalStateException("Debes iniciar sesion primero (opcion 2).");
        }
    }

    private static String obtenerExtension(String nombreArchivo) {
        int i = nombreArchivo.lastIndexOf('.');
        return (i >= 0) ? nombreArchivo.substring(i + 1) : "";
    }
}
