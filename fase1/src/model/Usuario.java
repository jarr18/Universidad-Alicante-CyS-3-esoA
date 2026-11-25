package model;

public class Usuario {
    private String nombreUsuario;
    private byte[] clavePublica;              // Ku, en claro
    private byte[] ivClavePrivada;
    private byte[] clavePrivadaProtegida;      // E^AES_{SHA3-256(pu)}(ku)

    public Usuario(String nombreUsuario, byte[] clavePublica,
                    byte[] ivClavePrivada, byte[] clavePrivadaProtegida) {
        this.nombreUsuario = nombreUsuario;
        this.clavePublica = clavePublica;
        this.ivClavePrivada = ivClavePrivada;
        this.clavePrivadaProtegida = clavePrivadaProtegida;
    }

    public String getNombreUsuario() { return nombreUsuario; }
    public byte[] getClavePublica() { return clavePublica; }
    public byte[] getIvClavePrivada() { return ivClavePrivada; }
    public byte[] getClavePrivadaProtegida() { return clavePrivadaProtegida; }
}
