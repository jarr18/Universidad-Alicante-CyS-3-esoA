import gui.VentanaPrincipal;
import service.CifradoService;

import javax.swing.*;

/** Punto de entrada de la interfaz grafica: java -cp out MainGui */
public class MainGui {
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignorada) {
            // Se queda con el aspecto por defecto de Swing
        }
        SwingUtilities.invokeLater(() -> new VentanaPrincipal(new CifradoService()).setVisible(true));
    }
}
