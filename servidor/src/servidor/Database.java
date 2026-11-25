package servidor;

import comun.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Persistencia del servidor: un fichero JSON (db.json) con usuarios, archivos y accesos,
 * y los archivos cifrados como blobs opacos en blobs/. El servidor NUNCA ve contenidos,
 * nombres ni claves de archivo en claro.
 */
final class Database {

    static final class Usuario {
        String nombre;
        String salt;               // sal del PBKDF (la elige el cliente), Base64
        int iteraciones;
        String saltServidor;       // sal propia del servidor para guardar el verificador
        String verificador;        // SHA3-256(saltServidor || mitad de autenticacion), Base64
        String clavePublica;       // Ku (X.509), Base64
        String clavePrivadaProtegida; // E^AES_(mitad de cifrado)(ku), Base64
        String totpSecretoCifrado; // secreto TOTP cifrado en reposo con la clave del servidor
        boolean totpActivo;
        long totpUltimoPaso;
        long creado;
    }

    static final class Archivo {
        String id;
        String propietario;
        String nombreCifrado;      // nombre del archivo cifrado con k_f (Base64)
        long tam;
        long creado;
    }

    /** Permiso de un usuario sobre un archivo: guarda E^RSA_Ku(k_f) para ESE usuario. */
    static final class Acceso {
        String archivoId;
        String usuario;
        String claveEnvuelta;      // Base64
        boolean propietario;
        String compartidoPor;
        long fecha;
    }

    private final Path dir;
    private final Path fichero;
    private final Path blobs;
    private final Map<String, Usuario> usuarios = new LinkedHashMap<>();
    private final Map<String, Archivo> archivos = new LinkedHashMap<>();
    private final List<Acceso> accesos = new ArrayList<>();

    Database(Path dir) throws IOException {
        this.dir = dir;
        this.fichero = dir.resolve("db.json");
        this.blobs = dir.resolve("blobs");
        Files.createDirectories(blobs);
        if (Files.exists(fichero)) cargar();
    }

    // ------------------------------------------------------------ usuarios

    synchronized Usuario usuario(String nombre) {
        return usuarios.get(nombre);
    }

    synchronized boolean crearUsuario(Usuario u) {
        if (usuarios.containsKey(u.nombre)) return false;
        usuarios.put(u.nombre, u);
        guardar();
        return true;
    }

    synchronized void actualizarUsuario() {
        guardar();
    }

    synchronized List<String> nombresUsuarios() {
        return new ArrayList<>(usuarios.keySet());
    }

    // ------------------------------------------------------------ archivos

    synchronized void crearArchivo(Archivo a, byte[] blob, Acceso propietario) throws IOException {
        Files.write(blobs.resolve(a.id + ".bin"), blob);
        archivos.put(a.id, a);
        accesos.add(propietario);
        guardar();
    }

    synchronized Archivo archivo(String id) {
        return archivos.get(id);
    }

    synchronized byte[] leerBlob(String id) throws IOException {
        return Files.readAllBytes(blobs.resolve(id + ".bin"));
    }

    synchronized Acceso acceso(String archivoId, String usuario) {
        for (Acceso x : accesos) if (x.archivoId.equals(archivoId) && x.usuario.equals(usuario)) return x;
        return null;
    }

    synchronized List<Acceso> accesosDeUsuario(String usuario) {
        List<Acceso> r = new ArrayList<>();
        for (Acceso x : accesos) if (x.usuario.equals(usuario)) r.add(x);
        return r;
    }

    synchronized List<Acceso> accesosDeArchivo(String archivoId) {
        List<Acceso> r = new ArrayList<>();
        for (Acceso x : accesos) if (x.archivoId.equals(archivoId)) r.add(x);
        return r;
    }

    synchronized void anadirAcceso(Acceso a) {
        accesos.add(a);
        guardar();
    }

    synchronized boolean quitarAcceso(String archivoId, String usuario) {
        boolean r = accesos.removeIf(x -> x.archivoId.equals(archivoId) && x.usuario.equals(usuario));
        if (r) guardar();
        return r;
    }

    synchronized void borrarArchivo(String id) throws IOException {
        archivos.remove(id);
        accesos.removeIf(x -> x.archivoId.equals(id));
        Files.deleteIfExists(blobs.resolve(id + ".bin"));
        guardar();
    }

    // --------------------------------------------------------- persistencia

    private void guardar() {
        try {
            List<Object> us = new ArrayList<>(), as = new ArrayList<>(), cs = new ArrayList<>();
            for (Usuario u : usuarios.values()) {
                us.add(Json.obj("nombre", u.nombre, "salt", u.salt, "iteraciones", u.iteraciones,
                        "saltServidor", u.saltServidor, "verificador", u.verificador,
                        "clavePublica", u.clavePublica, "clavePrivadaProtegida", u.clavePrivadaProtegida,
                        "totpSecretoCifrado", u.totpSecretoCifrado, "totpActivo", u.totpActivo,
                        "totpUltimoPaso", u.totpUltimoPaso, "creado", u.creado));
            }
            for (Archivo a : archivos.values()) {
                as.add(Json.obj("id", a.id, "propietario", a.propietario, "nombreCifrado", a.nombreCifrado,
                        "tam", a.tam, "creado", a.creado));
            }
            for (Acceso c : accesos) {
                cs.add(Json.obj("archivoId", c.archivoId, "usuario", c.usuario, "claveEnvuelta", c.claveEnvuelta,
                        "propietario", c.propietario, "compartidoPor", c.compartidoPor, "fecha", c.fecha));
            }
            String json = Json.texto(Json.obj("usuarios", us, "archivos", as, "accesos", cs));
            Path tmp = dir.resolve("db.json.tmp");
            Files.writeString(tmp, json, StandardCharsets.UTF_8);
            Files.move(tmp, fichero, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new IllegalStateException("No se pudo guardar la base de datos", e);
        }
    }

    @SuppressWarnings("unchecked")
    private void cargar() throws IOException {
        Map<String, Object> raiz = Json.parseObjeto(Files.readString(fichero, StandardCharsets.UTF_8));
        for (Object o : (List<Object>) raiz.getOrDefault("usuarios", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            Usuario u = new Usuario();
            u.nombre = Json.str(m, "nombre");
            u.salt = Json.str(m, "salt");
            u.iteraciones = (int) Json.num(m, "iteraciones", 0);
            u.saltServidor = Json.str(m, "saltServidor");
            u.verificador = Json.str(m, "verificador");
            u.clavePublica = Json.str(m, "clavePublica");
            u.clavePrivadaProtegida = Json.str(m, "clavePrivadaProtegida");
            u.totpSecretoCifrado = Json.str(m, "totpSecretoCifrado");
            u.totpActivo = Json.bool(m, "totpActivo");
            u.totpUltimoPaso = Json.num(m, "totpUltimoPaso", 0);
            u.creado = Json.num(m, "creado", 0);
            usuarios.put(u.nombre, u);
        }
        for (Object o : (List<Object>) raiz.getOrDefault("archivos", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            Archivo a = new Archivo();
            a.id = Json.str(m, "id");
            a.propietario = Json.str(m, "propietario");
            a.nombreCifrado = Json.str(m, "nombreCifrado");
            a.tam = Json.num(m, "tam", 0);
            a.creado = Json.num(m, "creado", 0);
            archivos.put(a.id, a);
        }
        for (Object o : (List<Object>) raiz.getOrDefault("accesos", List.of())) {
            Map<String, Object> m = (Map<String, Object>) o;
            Acceso c = new Acceso();
            c.archivoId = Json.str(m, "archivoId");
            c.usuario = Json.str(m, "usuario");
            c.claveEnvuelta = Json.str(m, "claveEnvuelta");
            c.propietario = Json.bool(m, "propietario");
            c.compartidoPor = Json.str(m, "compartidoPor");
            c.fecha = Json.num(m, "fecha", 0);
            accesos.add(c);
        }
    }
}
