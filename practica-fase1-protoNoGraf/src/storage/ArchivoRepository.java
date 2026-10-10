package storage;

import model.ArchivoCifrado;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Persiste el registro de los archivos cifrados en un fichero de texto
 * (archivos.txt), una linea por archivo. El contenido cifrado c_i NO se
 * guarda aqui: vive en un fichero binario .enc en disco y esta linea
 * solo guarda su ruta.
 *
 * Formato de cada linea:
 *   id|nombreUsuario|nombreOriginal|extension|Base64(iv)|Base64(E_RSA_Ku(k_fi))|rutaDelFicheroEnc
 *
 * Al descifrar un archivo su linea se ELIMINA (eliminar), con lo que se
 * pierde E_RSA_Ku(k_fi): sin esa clave el .enc ya no se puede descifrar
 * hasta que el archivo se vuelva a cifrar (con una k_fi nueva).
 */
public class ArchivoRepository {

    private static final Path FICHERO = Path.of("data", "archivos.txt");
    private static final String SEPARADOR = "\\|";

    /** Extension que reciben los archivos al cifrarse. */
    public static final String EXTENSION_CIFRADO = ".enc";

    public ArchivoRepository() {
        try {
            Files.createDirectories(FICHERO.getParent());
            if (!Files.exists(FICHERO)) {
                Files.createFile(FICHERO);
            }
        } catch (IOException e) {
            throw new RuntimeException("No se pudo preparar el fichero de archivos", e);
        }
    }

    public int guardar(ArchivoCifrado a) {
        int nuevoId = siguienteId();
        String linea = String.join("|",
                String.valueOf(nuevoId),
                a.getNombreUsuarioPropietario(),
                a.getNombreOriginal(),
                a.getExtension() == null ? "" : a.getExtension(),
                Base64.getEncoder().encodeToString(a.getIvArchivo()),
                Base64.getEncoder().encodeToString(a.getClaveArchivoProtegida()),
                a.getRutaCifrado());
        try {
            Files.writeString(FICHERO, linea + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException("Error guardando el archivo", e);
        }
        return nuevoId;
    }

    /** Borra el registro (y con el, la clave protegida) del archivo con ese id. */
    public void eliminar(int id) {
        try {
            List<String> lineas = Files.readAllLines(FICHERO, StandardCharsets.UTF_8);
            List<String> restantes = new ArrayList<>();
            for (String linea : lineas) {
                if (!linea.isBlank() && idDeLinea(linea) == id) continue;
                restantes.add(linea);
            }
            Path tmp = FICHERO.resolveSibling("archivos.txt.tmp");
            Files.write(tmp, restantes, StandardCharsets.UTF_8);
            Files.move(tmp, FICHERO, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Error eliminando el registro del archivo", e);
        }
    }

    public List<ArchivoCifrado> listarPorUsuario(String nombreUsuario) {
        List<ArchivoCifrado> resultado = new ArrayList<>();
        for (ArchivoCifrado a : leerTodos()) {
            if (a.getNombreUsuarioPropietario().equals(nombreUsuario)) {
                resultado.add(a);
            }
        }
        return resultado;
    }

    public Optional<ArchivoCifrado> buscarPorId(int id) {
        for (ArchivoCifrado a : leerTodos()) {
            if (a.getId() == id) return Optional.of(a);
        }
        return Optional.empty();
    }

    private int siguienteId() {
        int max = 0;
        for (ArchivoCifrado a : leerTodos()) {
            max = Math.max(max, a.getId());
        }
        return max + 1;
    }

    private static int idDeLinea(String linea) {
        try {
            return Integer.parseInt(linea.split(SEPARADOR, 2)[0]);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private List<ArchivoCifrado> leerTodos() {
        List<ArchivoCifrado> lista = new ArrayList<>();
        try {
            List<String> lineas = Files.readAllLines(FICHERO, StandardCharsets.UTF_8);
            for (String linea : lineas) {
                if (linea.isBlank()) continue;
                String[] c = linea.split(SEPARADOR, -1);
                if (c.length != 7) continue;
                // El formato antiguo guardaba aqui el contenido en Base64 (nunca contiene '.')
                if (!c[6].endsWith(EXTENSION_CIFRADO)) continue;
                try {
                    lista.add(new ArchivoCifrado(
                            Integer.parseInt(c[0]),
                            c[1],
                            c[2],
                            c[3],
                            Base64.getDecoder().decode(c[4]),
                            Base64.getDecoder().decode(c[5]),
                            c[6]));
                } catch (IllegalArgumentException e) {
                    // Linea con formato antiguo (contenido en Base64) o corrupta: se ignora
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error leyendo el fichero de archivos", e);
        }
        return lista;
    }
}
