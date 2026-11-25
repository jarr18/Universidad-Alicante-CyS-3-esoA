package pruebas;

import cliente.ClienteServicio;
import cliente.gui.VentanaLogin;
import cliente.gui.VentanaPrincipal;
import com.sun.net.httpserver.HttpServer;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Random;

/**
 * Genera las capturas del manual de usuario con la interfaz REAL (arranca un servidor de
 * prueba y abre las ventanas del cliente). Requiere pantalla (en Linux: xvfb-run).
 * Uso: java -cp ... pruebas.CapturasManual carpeta-salida
 */
public class CapturasManual {

    static Robot robot;
    static Path salida;

    public static void main(String[] args) throws Exception {
        Locale.setDefault(Locale.of("es", "ES"));
        salida = Path.of(args.length > 0 ? args[0] : "capturas");
        Files.createDirectories(salida);
        UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
        robot = new Robot();
        Path datos = Files.createTempDirectory("cys-capt-");
        HttpServer srv = servidor.ServidorMain.iniciar(datos, "127.0.0.1", 0, null, null);
        String url = "http://127.0.0.1:" + srv.getAddress().getPort();

        ClienteServicio bob = new ClienteServicio(url);
        bob.registrar("bob", "contrasena-de-bob");
        new ClienteServicio(url).registrar("carol", "contrasena-de-carol");
        ClienteServicio alice = new ClienteServicio(url);
        alice.registrar("alice", "contrasena-de-alice");
        alice.iniciarSesion("alice", "contrasena-de-alice");
        Path tmp = Files.createTempDirectory("cys-ej-");
        String[] nombres = {"vacaciones-2026.jpg", "entrevista.mp3", "presentacion.mp4", "concierto.mp4"};
        int[] tam = {2_400_000, 5_100_000, 18_000_000, 9_500_000};
        String idPresent = null;
        for (int i = 0; i < nombres.length; i++) {
            byte[] b = new byte[tam[i]];
            new Random(i).nextBytes(b);
            Files.write(tmp.resolve(nombres[i]), b);
            String id = alice.subir(tmp.resolve(nombres[i]));
            if (i == 2) idPresent = id;
            Thread.sleep(30);
        }
        alice.compartir(idPresent, "bob");

        VentanaLogin login = new VentanaLogin();
        mostrar(login);
        pausa(600);
        foto(login, "01-acceso.png");
        login.dispose();

        VentanaPrincipal vp = new VentanaPrincipal(alice);
        mostrar(vp);
        pausa(2500);
        JTable tabla = (JTable) buscar(vp.getContentPane(), JTable.class);
        SwingUtilities.invokeAndWait(() -> tabla.setRowSelectionInterval(1, 1));
        pausa(400);
        foto(vp, "02-principal.png");

        pulsar(vp, "Compartir…");
        pausa(2500);
        fotoDialogo("03-compartir.png");
        cerrarDialogos();
        pausa(500);

        pulsar(vp, "Seguridad (2FA)…");
        pausa(1800);
        fotoDialogo("04-seguridad.png");
        pulsarDialogo("Sí");
        pausa(2500);
        fotoDialogo("05-activar-2fa.png");
        cerrarDialogos();
        pausa(500);

        vp.dispose();
        bob.iniciarSesion("bob", "contrasena-de-bob");
        VentanaPrincipal vb = new VentanaPrincipal(bob);
        mostrar(vb);
        pausa(2500);
        foto(vb, "06-recibido.png");
        vb.dispose();
        srv.stop(0);
        System.out.println("Capturas en " + salida.toAbsolutePath());
        System.exit(0);
    }

    static void mostrar(Window w) throws Exception {
        SwingUtilities.invokeAndWait(() -> { w.setLocation(120, 80); w.setVisible(true); });
    }

    static void pausa(int ms) throws Exception {
        Thread.sleep(ms);
    }

    static void foto(Window w, String nombre) throws Exception {
        Rectangle r = w.getBounds();
        BufferedImage img = robot.createScreenCapture(r);
        ImageIO.write(img, "png", new File(salida.toFile(), nombre));
    }

    static void fotoDialogo(String nombre) throws Exception {
        for (Window w : Window.getWindows()) {
            if (w instanceof JDialog d && d.isShowing()) {
                foto(d, nombre);
                return;
            }
        }
        System.err.println("No hay dialogo para " + nombre);
    }

    static void cerrarDialogos() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (Window w : Window.getWindows()) if (w instanceof JDialog d && d.isShowing()) d.dispose();
        });
    }

    static void pulsar(Container raiz, String texto) throws Exception {
        JButton b = (JButton) buscarBoton(raiz, texto);
        SwingUtilities.invokeLater(b::doClick);
    }

    static void pulsarDialogo(String texto) throws Exception {
        for (Window w : Window.getWindows()) {
            if (w instanceof JDialog d && d.isShowing()) {
                JButton b = (JButton) buscarBoton(d.getContentPane(), texto);
                if (b != null) { SwingUtilities.invokeLater(b::doClick); return; }
            }
        }
    }

    static Component buscar(Container c, Class<?> tipo) {
        for (Component x : c.getComponents()) {
            if (tipo.isInstance(x)) return x;
            if (x instanceof Container cc) {
                Component r = buscar(cc, tipo);
                if (r != null) return r;
            }
        }
        return null;
    }

    static Component buscarBoton(Container c, String texto) {
        for (Component x : c.getComponents()) {
            if (x instanceof JButton b && texto.equals(b.getText())) return b;
            if (x instanceof Container cc) {
                Component r = buscarBoton(cc, texto);
                if (r != null) return r;
            }
        }
        return null;
    }
}
