package storage;

import model.Usuario;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Persiste los usuarios en un fichero de texto plano (usuarios.txt),
 * una linea por usuario, con los campos separados por "|" y los datos
 * binarios (claves, IV) codificados en Base64.
 *
 * Formato de cada linea:
 *   nombreUsuario|Base64(Ku)|Base64(ivClavePrivada)|Base64(E_AES_pu(ku))
 */
public class UsuarioRepository {

    private static final Path FICHERO = Path.of("data", "usuarios.txt");
    private static final String SEPARADOR = "\\|";

    public UsuarioRepository() {
        try {
            Files.createDirectories(FICHERO.getParent());
            if (!Files.exists(FICHERO)) {
                Files.createFile(FICHERO);
            }
        } catch (IOException e) {
            throw new RuntimeException("No se pudo preparar el fichero de usuarios", e);
        }
    }

    public void guardar(Usuario u) {
        if (existe(u.getNombreUsuario())) {
            throw new IllegalArgumentException("El usuario ya existe");
        }
        String linea = String.join("|",
                u.getNombreUsuario(),
                Base64.getEncoder().encodeToString(u.getClavePublica()),
                Base64.getEncoder().encodeToString(u.getIvClavePrivada()),
                Base64.getEncoder().encodeToString(u.getClavePrivadaProtegida()));
        try {
            Files.writeString(FICHERO, linea + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new RuntimeException("Error guardando el usuario", e);
        }
    }

    public boolean existe(String nombreUsuario) {
        return buscarPorNombre(nombreUsuario).isPresent();
    }

    public Optional<Usuario> buscarPorNombre(String nombreUsuario) {
        try {
            List<String> lineas = Files.readAllLines(FICHERO, StandardCharsets.UTF_8);
            for (String linea : lineas) {
                if (linea.isBlank()) continue;
                String[] campos = linea.split(SEPARADOR, -1);
                if (campos.length != 4) continue;
                if (campos[0].equals(nombreUsuario)) {
                    return Optional.of(new Usuario(
                            campos[0],
                            Base64.getDecoder().decode(campos[1]),
                            Base64.getDecoder().decode(campos[2]),
                            Base64.getDecoder().decode(campos[3])));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error leyendo el fichero de usuarios", e);
        }
        return Optional.empty();
    }
}
