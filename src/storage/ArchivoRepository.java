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
 * Persiste los archivos cifrados en un fichero de texto plano
 * (archivos.txt), una linea por archivo, con los datos binarios
 * (IV, clave de archivo protegida y contenido cifrado) en Base64.
 *
 * Formato de cada linea:
 *   id|nombreUsuario|nombreOriginal|extension|Base64(iv)|Base64(E_RSA_Ku(k_fi))|Base64(c_i)
 *
 * NOTA: para simplificar al maximo, el contenido cifrado del archivo se
 * guarda tambien en Base64 dentro de la misma linea de texto. Para
 * archivos muy grandes esto no seria lo mas eficiente (lo normal seria
 * guardar c_i en un fichero binario aparte), pero para esta practica
 * es la opcion mas sencilla de entender y depurar.
 */
public class ArchivoRepository {

    private static final Path FICHERO = Path.of("data", "archivos.txt");
    private static final String SEPARADOR = "\\|";

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
                Base64.getEncoder().encodeToString(a.getContenidoCifrado()));
        try {
            Files.writeString(FICHERO, linea + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException("Error guardando el archivo", e);
        }
        return nuevoId;
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

    private List<ArchivoCifrado> leerTodos() {
        List<ArchivoCifrado> lista = new ArrayList<>();
        try {
            List<String> lineas = Files.readAllLines(FICHERO, StandardCharsets.UTF_8);
            for (String linea : lineas) {
                if (linea.isBlank()) continue;
                String[] c = linea.split(SEPARADOR, -1);
                if (c.length != 7) continue;
                lista.add(new ArchivoCifrado(
                        Integer.parseInt(c[0]),
                        c[1],
                        c[2],
                        c[3],
                        Base64.getDecoder().decode(c[4]),
                        Base64.getDecoder().decode(c[5]),
                        Base64.getDecoder().decode(c[6])));
            }
        } catch (IOException e) {
            throw new RuntimeException("Error leyendo el fichero de archivos", e);
        }
        return lista;
    }
}
