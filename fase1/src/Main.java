import model.ArchivoCifrado;
import service.CifradoService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Scanner;

/**
 * Practica Fase I - Compresion y Seguridad
 * Interfaz de consola. Toda la logica criptografica y de ficheros esta en
 * service.CifradoService (la misma que usa la interfaz grafica, MainGui).
 *
 * Flujo implementado (ver diagrama del PDF):
 *   - Un unico usuario con su password. La primera vez que arranca el
 *     programa se genera su par RSA (Ku, ku); ku se protege cifrandola con
 *     AES-128, usando como clave SHA3-256(password).
 *   - Login: se recalcula SHA3-256(password) y se intenta descifrar ku;
 *     si falla, el password es incorrecto.
 *   - Cifrado: se genera k_fi (AES-128), se cifra el archivo con k_fi y
 *     se escribe como .enc (el original se elimina). k_fi se protege con Ku (RSA).
 *   - Descifrado: se recupera k_fi con ku (RSA) y se restaura el original;
 *     el .enc y la clave protegida se eliminan (un solo uso por cifrado).
 */
public class Main {

    private static final Scanner SC = new Scanner(System.in);
    private static final CifradoService servicio = new CifradoService();

    public static void main(String[] args) {
        System.out.println("=== PRACTICA FASE I - Compresion y Seguridad (version sin BD) ===");
        System.out.println("Los datos se guardan en la carpeta 'data/' (usuarios.txt y archivos.txt).");
        boolean salir = false;
        while (!salir) {
            mostrarMenu();
            String opcion = SC.nextLine().trim();
            try {
                switch (opcion) {
                    case "1" -> iniciarSesion();
                    case "2" -> cifrarArchivo();
                    case "3" -> descifrarArchivo();
                    case "4" -> listarArchivos();
                    case "5" -> cerrarSesion();
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
        System.out.println("Sesion: " + (servicio.haySesion() ? servicio.getNombreUsuario() : "(no autenticado)"));
        System.out.println("1. Iniciar sesion");
        System.out.println("2. Cifrar archivo (se reemplaza por un .enc)");
        System.out.println("3. Descifrar archivo (restaura el original)");
        System.out.println("4. Listar mis archivos cifrados");
        System.out.println("5. Cerrar sesion");
        System.out.println("0. Salir");
        System.out.print("Elige una opcion: ");
    }

    private static void iniciarSesion() {
        System.out.print("Nombre de usuario: ");
        String nombre = SC.nextLine().trim();
        System.out.print("Password: ");
        String password = SC.nextLine();
        servicio.iniciarSesion(nombre, password);
        System.out.println("Sesion iniciada como '" + nombre + "'.");
    }

    private static void cifrarArchivo() throws IOException {
        System.out.print("Ruta del archivo a cifrar: ");
        Path ruta = Path.of(SC.nextLine().trim());
        CifradoService.ResultadoCifrado r = servicio.cifrar(ruta);
        System.out.println("Archivo cifrado con id=" + r.id() + ".");
        System.out.println("  " + ruta.getFileName() + "  ->  " + r.rutaEnc().getFileName());
        System.out.println("  El original ha sido eliminado; solo existe la version cifrada.");
    }

    private static void descifrarArchivo() throws IOException {
        listarArchivos();
        System.out.print("Id del archivo a descifrar: ");
        int id = Integer.parseInt(SC.nextLine().trim());
        System.out.print("Carpeta de destino (Enter = la del .enc): ");
        String entrada = SC.nextLine().trim();
        Path destino = servicio.descifrar(id, entrada.isEmpty() ? null : Path.of(entrada));
        System.out.println("Archivo descifrado en: " + destino);
        System.out.println("  El .enc y su clave se han eliminado. Para volver a descifrarlo hay que cifrarlo de nuevo.");
    }

    private static void listarArchivos() {
        List<ArchivoCifrado> archivos = servicio.listar();
        if (archivos.isEmpty()) {
            System.out.println("No tienes archivos cifrados.");
            return;
        }
        System.out.println("Tus archivos cifrados:");
        for (ArchivoCifrado a : archivos) {
            System.out.printf("  id=%d  %s  (%s)%n", a.getId(), a.getNombreOriginal(), a.getRutaCifrado());
        }
    }

    private static void cerrarSesion() {
        servicio.cerrarSesion();
        System.out.println("Sesion cerrada.");
    }
}
