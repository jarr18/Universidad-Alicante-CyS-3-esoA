package cliente;

import cliente.gui.VentanaLogin;

import javax.swing.*;

/** Punto de entrada del cliente: java -cp out/cliente cliente.MainCliente */
public class MainCliente {
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignorada) {
            // aspecto por defecto de Swing
        }
        SwingUtilities.invokeLater(() -> new VentanaLogin().setVisible(true));
    }
}
