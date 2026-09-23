package model;

public class ArchivoCifrado {
    private int id;
    private String nombreUsuarioPropietario;
    private String nombreOriginal;
    private String extension;
    private byte[] ivArchivo;
    private byte[] claveArchivoProtegida;     // E_{Ku}^{RSA}(k_fi)
    private byte[] contenidoCifrado;          // c_i = E_{k_fi}^{AES}(f_i)

    public ArchivoCifrado(int id, String nombreUsuarioPropietario, String nombreOriginal,
                           String extension, byte[] ivArchivo,
                           byte[] claveArchivoProtegida, byte[] contenidoCifrado) {
        this.id = id;
        this.nombreUsuarioPropietario = nombreUsuarioPropietario;
        this.nombreOriginal = nombreOriginal;
        this.extension = extension;
        this.ivArchivo = ivArchivo;
        this.claveArchivoProtegida = claveArchivoProtegida;
        this.contenidoCifrado = contenidoCifrado;
    }

    public int getId() { return id; }
    public String getNombreUsuarioPropietario() { return nombreUsuarioPropietario; }
    public String getNombreOriginal() { return nombreOriginal; }
    public String getExtension() { return extension; }
    public byte[] getIvArchivo() { return ivArchivo; }
    public byte[] getClaveArchivoProtegida() { return claveArchivoProtegida; }
    public byte[] getContenidoCifrado() { return contenidoCifrado; }
}
