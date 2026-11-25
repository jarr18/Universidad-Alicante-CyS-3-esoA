package cliente.net;

/** Error devuelto por el servidor (estado HTTP + mensaje) o de comunicacion (estado 0). */
public class ApiException extends RuntimeException {
    private final int estado;

    public ApiException(int estado, String mensaje) {
        super(mensaje);
        this.estado = estado;
    }

    public int getEstado() {
        return estado;
    }
}
