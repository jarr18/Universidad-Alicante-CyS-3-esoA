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
 *   - Subida de archivo: se genera k_fi (AES-128), se cifra el archivo
 *     con k_fi, y k_fi se protege cifrandola con la clave publica Ku (RSA).
 *   - Descarga: se descifra k_fi con la clave privada ku (RSA), y con
 *     k_fi se descifra el contenido del archivo (AES).
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
        System.out.println("3. Cifrar y subir archivo");
        System.out.println("4. Descargar y descifrar archivo");
        System.out.println("5. Listar mis archivos");
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
    // 3. Subir archivo (cifrar)
    // ---------------------------------------------------------------
    private static void subirArchivo() throws IOException {
        requiereSesion();
        System.out.print("Ruta del archivo a cifrar y subir: ");
        Path ruta = Path.of(SC.nextLine().trim());
        if (!Files.exists(ruta)) {
            System.out.println("El archivo no existe.");
            return;
        }

        byte[] contenido = Files.readAllBytes(ruta);
        String nombreCompleto = ruta.getFileName().toString();
        String extension = obtenerExtension(nombreCompleto);

        // Generar clave de archivo k_fi (AES-128) y cifrar f_i
        SecretKey claveArchivo = AesUtil.generarClave();
        byte[] iv = AesUtil.generarIv();
        byte[] contenidoCifrado = AesUtil.cifrar(contenido, claveArchivo, iv);

        // Proteger k_fi con la clave publica RSA del usuario: E_{Ku}^{RSA}(k_fi)
        PublicKey publica = RsaUtil.publicaDesdeBytes(usuarioActual.getClavePublica());
        byte[] claveArchivoProtegida = RsaUtil.cifrarConPublica(claveArchivo.getEncoded(), publica);

        ArchivoCifrado archivo = new ArchivoCifrado(
                0, usuarioActual.getNombreUsuario(), nombreCompleto, extension,
                iv, claveArchivoProtegida, contenidoCifrado);

        int id = archivoRepo.guardar(archivo);
        System.out.println("Archivo cifrado y guardado con id=" + id + ".");
    }

    // ---------------------------------------------------------------
    // 4. Descargar archivo (descifrar)
    // ---------------------------------------------------------------
    private static void descargarArchivo() throws IOException {
        requiereSesion();
        listarArchivos();
        System.out.print("Id del archivo a descargar: ");
        int id = Integer.parseInt(SC.nextLine().trim());

        ArchivoCifrado archivo = archivoRepo.buscarPorId(id)
                .filter(a -> a.getNombreUsuarioPropietario().equals(usuarioActual.getNombreUsuario()))
                .orElseThrow(() -> new IllegalArgumentException("Archivo no encontrado en tu lista"));

        // Recuperar k_fi descifrando con la clave privada del usuario
        byte[] claveArchivoBytes = RsaUtil.descifrarConPrivada(
                archivo.getClaveArchivoProtegida(), clavePrivadaActual);
        SecretKey claveArchivo = AesUtil.claveDesdeBytes(claveArchivoBytes);

        // Descifrar el contenido del archivo con k_fi
        byte[] contenido = AesUtil.descifrar(
                archivo.getContenidoCifrado(), claveArchivo, archivo.getIvArchivo());

        System.out.print("Carpeta de destino para guardar el archivo descifrado: ");
        String carpetaDestino = SC.nextLine().trim();
        Path destino = Path.of(carpetaDestino, archivo.getNombreOriginal());
        Files.write(destino, contenido);
        System.out.println("Archivo descifrado guardado en: " + destino);
    }

    // ---------------------------------------------------------------
    // 5. Listar archivos
    // ---------------------------------------------------------------
    private static void listarArchivos() {
        requiereSesion();
        List<ArchivoCifrado> archivos = archivoRepo.listarPorUsuario(usuarioActual.getNombreUsuario());
        if (archivos.isEmpty()) {
            System.out.println("No tienes archivos subidos todavia.");
            return;
        }
        System.out.println("Tus archivos:");
        for (ArchivoCifrado a : archivos) {
            System.out.printf("  id=%d  %s%n", a.getId(), a.getNombreOriginal());
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
