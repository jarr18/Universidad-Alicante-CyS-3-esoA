package cliente.gui;

import cliente.ClienteServicio;
import cliente.ClienteServicio.ArchivoInfo;
import cliente.net.ApiException;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Ventana principal: lista de archivos cifrados y acciones (subir, abrir, descargar, compartir, 2FA). */
public class VentanaPrincipal extends JFrame {

    private final ClienteServicio servicio;
    private final List<ArchivoInfo> archivos = new ArrayList<>();
    private final String[] columnas = {"Nombre", "Propietario", "Tamaño", "Fecha", "Compartido con"};
    private final AbstractTableModel modelo = new AbstractTableModel() {
        public int getRowCount() { return archivos.size(); }
        public int getColumnCount() { return columnas.length; }
        public String getColumnName(int c) { return columnas[c]; }
        public Object getValueAt(int r, int c) {
            ArchivoInfo a = archivos.get(r);
            return switch (c) {
                case 0 -> a.nombre();
                case 1 -> a.esPropio() ? "Yo" : a.propietario();
                case 2 -> Ayuda.tamano(a.tam());
                case 3 -> Ayuda.fecha(a.creado());
                default -> a.esPropio() ? String.join(", ", a.compartidoCon()) : "(compartido contigo)";
            };
        }
    };
    private final JTable tabla = new JTable(modelo);
    private final JLabel estado = new JLabel(" ");
    private final JButton btnSubir = new JButton("Subir y cifrar…");
    private final JButton btnAbrir = new JButton("Abrir");
    private final JButton btnDescargar = new JButton("Descargar y descifrar…");
    private final JButton btnCompartir = new JButton("Compartir…");
    private final JButton btnQuitar = new JButton("Dejar de compartir…");
    private final JButton btnEliminar = new JButton("Eliminar");
    private final JButton btnActualizar = new JButton("Actualizar");
    private final JButton btnSeguridad = new JButton("Seguridad (2FA)…");
    private final JButton btnSalir = new JButton("Cerrar sesión");

    public VentanaPrincipal(ClienteServicio servicio) {
        super("Servicio seguro de contenidos multimedia — " + servicio.getUsuario());
        this.servicio = servicio;
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                salir(false);
            }
        });
        tabla.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tabla.setRowHeight(24);
        tabla.getSelectionModel().addListSelectionListener(e -> botones());
        tabla.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2 && seleccionado() != null) abrir();
            }
        });
        JPanel barra = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        for (JButton b : new JButton[]{btnSubir, btnAbrir, btnDescargar, btnCompartir, btnQuitar, btnEliminar, btnActualizar, btnSeguridad, btnSalir})
            barra.add(b);
        add(barra, BorderLayout.NORTH);
        add(new JScrollPane(tabla), BorderLayout.CENTER);
        estado.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        add(estado, BorderLayout.SOUTH);
        btnSubir.addActionListener(e -> subir());
        btnAbrir.addActionListener(e -> abrir());
        btnDescargar.addActionListener(e -> descargar());
        btnCompartir.addActionListener(e -> compartir());
        btnQuitar.addActionListener(e -> quitar());
        btnEliminar.addActionListener(e -> eliminar());
        btnActualizar.addActionListener(e -> refrescar());
        btnSeguridad.addActionListener(e -> seguridad());
        btnSalir.addActionListener(e -> salir(true));
        setSize(1100, 480);
        setLocationRelativeTo(null);
        botones();
        refrescar();
    }

    private ArchivoInfo seleccionado() {
        int f = tabla.getSelectedRow();
        return f >= 0 && f < archivos.size() ? archivos.get(f) : null;
    }

    private void botones() {
        ArchivoInfo a = seleccionado();
        boolean hay = a != null, propio = hay && a.esPropio();
        btnAbrir.setEnabled(hay);
        btnDescargar.setEnabled(hay);
        btnCompartir.setEnabled(propio);
        btnQuitar.setEnabled(propio && !a.compartidoCon().isEmpty());
        btnEliminar.setEnabled(hay);
        btnEliminar.setText(hay && !a.esPropio() ? "Quitar de mi lista" : "Eliminar");
    }

    private <T> void ejecutar(String mensaje, java.util.concurrent.Callable<T> tarea, java.util.function.Consumer<T> fin) {
        estado.setText(mensaje);
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        for (JButton b : new JButton[]{btnSubir, btnAbrir, btnDescargar, btnCompartir, btnQuitar, btnEliminar, btnActualizar, btnSeguridad})
            b.setEnabled(false);
        Ayuda.segundoPlano(tarea, r -> {
            setCursor(Cursor.getDefaultCursor());
            btnSubir.setEnabled(true);
            btnActualizar.setEnabled(true);
            btnSeguridad.setEnabled(true);
            botones();
            fin.accept(r);
        }, t -> {
            setCursor(Cursor.getDefaultCursor());
            btnSubir.setEnabled(true);
            btnActualizar.setEnabled(true);
            btnSeguridad.setEnabled(true);
            botones();
            estado.setText("Error");
            Ayuda.error(this, t);
            if (t instanceof ApiException e && e.getEstado() == 401) salir(true);
            else if (t instanceof IllegalStateException) salir(true);
        });
    }

    private void refrescar() {
        ejecutar("Actualizando lista…", servicio::listar, lista -> {
            archivos.clear();
            archivos.addAll(lista);
            modelo.fireTableDataChanged();
            estado.setText(lista.size() + " archivo(s) · sesión de «" + servicio.getUsuario() + "»");
            botones();
        });
    }

    private void subir() {
        JFileChooser fc = new JFileChooser();
        fc.setMultiSelectionEnabled(true);
        fc.setDialogTitle("Selecciona los archivos que quieres cifrar y subir");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File[] fs = fc.getSelectedFiles();
        ejecutar("Cifrando y subiendo " + fs.length + " archivo(s)…", () -> {
            List<String> fallos = new ArrayList<>();
            for (File f : fs) {
                try {
                    servicio.subir(f.toPath());
                } catch (Exception e) {
                    fallos.add(f.getName() + ": " + ClienteServicio.mensaje(e));
                }
            }
            return fallos;
        }, fallos -> {
            if (!fallos.isEmpty())
                JOptionPane.showMessageDialog(this, "No se pudieron subir:\n" + String.join("\n", fallos), "Aviso", JOptionPane.WARNING_MESSAGE);
            else if (JOptionPane.showConfirmDialog(this, "Subida completada.\n¿Quieres borrar los originales sin cifrar de tu equipo?",
                    "Originales", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION)
                for (File f : fs) f.delete();
            refrescar();
        });
    }

    private void abrir() {
        ArchivoInfo a = seleccionado();
        if (a == null) return;
        ejecutar("Descargando y descifrando «" + a.nombre() + "»…", () -> servicio.descifrarATemporal(a.id()), ruta -> {
            estado.setText("Abierto: " + a.nombre() + " (copia temporal; se borra al cerrar sesión)");
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) Desktop.getDesktop().open(ruta.toFile());
                else JOptionPane.showMessageDialog(this, "Archivo descifrado en:\n" + ruta, "Abrir", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                Ayuda.error(this, e);
            }
        });
    }

    private void descargar() {
        ArchivoInfo a = seleccionado();
        if (a == null) return;
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fc.setDialogTitle("Carpeta donde guardar el archivo descifrado");
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path carpeta = fc.getSelectedFile().toPath();
        ejecutar("Descargando y descifrando…", () -> servicio.guardarEn(a.id(), carpeta), ruta ->
                JOptionPane.showMessageDialog(this, "Archivo descifrado en:\n" + ruta, "Descifrado correcto", JOptionPane.INFORMATION_MESSAGE));
    }

    private void compartir() {
        ArchivoInfo a = seleccionado();
        if (a == null) return;
        ejecutar("Cargando usuarios…", servicio::usuarios, todos -> {
            List<String> libres = new ArrayList<>(todos);
            libres.removeAll(a.compartidoCon());
            if (libres.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No hay más usuarios con los que compartir este archivo.");
                return;
            }
            Object dest = JOptionPane.showInputDialog(this, "¿Con quién quieres compartir «" + a.nombre() + "»?\n"
                            + "(El archivo no se vuelve a cifrar: solo se entrega su clave protegida al destinatario)",
                    "Compartir", JOptionPane.QUESTION_MESSAGE, null, libres.toArray(), libres.get(0));
            if (dest == null) return;
            ejecutar("Compartiendo con " + dest + "…", () -> { servicio.compartir(a.id(), dest.toString()); return null; }, x -> refrescar());
        });
    }

    private void quitar() {
        ArchivoInfo a = seleccionado();
        if (a == null || a.compartidoCon().isEmpty()) return;
        Object dest = JOptionPane.showInputDialog(this, "¿A quién quieres quitar el acceso a «" + a.nombre() + "»?",
                "Dejar de compartir", JOptionPane.QUESTION_MESSAGE, null, a.compartidoCon().toArray(), a.compartidoCon().get(0));
        if (dest == null) return;
        ejecutar("Quitando acceso…", () -> { servicio.dejarDeCompartir(a.id(), dest.toString()); return null; }, x -> refrescar());
    }

    private void eliminar() {
        ArchivoInfo a = seleccionado();
        if (a == null) return;
        String txt = a.esPropio()
                ? "¿Eliminar «" + a.nombre() + "» del servidor?\nTambién dejará de estar disponible para quienes lo tengan compartido."
                : "¿Quitar «" + a.nombre() + "» de tu lista?\n(El propietario lo conserva.)";
        if (JOptionPane.showConfirmDialog(this, txt, "Confirmar", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) return;
        ejecutar("Eliminando…", () -> { servicio.eliminar(a.id()); return null; }, x -> refrescar());
    }

    private void seguridad() {
        ejecutar("Consultando el estado del 2FA…", servicio::dobleFactorActivo, activo -> {
            if (activo) {
                String c = JOptionPane.showInputDialog(this, "El 2FA está ACTIVADO.\nPara desactivarlo, introduce un código de 6 dígitos:",
                        "Segundo factor (2FA)", JOptionPane.QUESTION_MESSAGE);
                if (c != null) ejecutar("Desactivando 2FA…", () -> { servicio.desactivar2fa(c.trim()); return null; }, x ->
                        JOptionPane.showMessageDialog(this, "2FA desactivado."));
            } else if (JOptionPane.showConfirmDialog(this, "El 2FA está desactivado. ¿Quieres activarlo ahora?\n"
                    + "Necesitarás una aplicación de autenticación (Google Authenticator, Authy, Microsoft Authenticator…).",
                    "Segundo factor (2FA)", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                ejecutar("Generando secreto…", servicio::configurar2fa, this::confirmar2fa);
            }
        });
    }

    private void confirmar2fa(String[] datos) {
        JTextField secreto = new JTextField(datos[0]);
        secreto.setEditable(false);
        secreto.setFont(new Font(Font.MONOSPACED, Font.BOLD, 16));
        JTextField uri = new JTextField(datos[1]);
        uri.setEditable(false);
        JTextField codigo = new JTextField(8);
        JPanel p = new JPanel(new GridLayout(0, 1, 4, 4));
        p.add(new JLabel("1. En tu aplicación de autenticación añade una cuenta «manual» con esta clave:"));
        p.add(secreto);
        p.add(new JLabel("(o importa este enlace otpauth:)"));
        p.add(uri);
        p.add(new JLabel("2. Escribe el código de 6 dígitos que te muestra para confirmar:"));
        p.add(codigo);
        if (JOptionPane.showConfirmDialog(this, p, "Activar 2FA", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        ejecutar("Activando 2FA…", () -> { servicio.activar2fa(codigo.getText().trim()); return null; }, x ->
                JOptionPane.showMessageDialog(this, "2FA activado. Desde ahora se te pedirá el código al iniciar sesión."));
    }

    private void salir(boolean volverAlLogin) {
        Ayuda.segundoPlano(() -> { servicio.cerrarSesion(); return null; }, x -> {
            dispose();
            if (volverAlLogin) new VentanaLogin().setVisible(true);
            else System.exit(0);
        }, x -> {
            dispose();
            if (volverAlLogin) new VentanaLogin().setVisible(true);
            else System.exit(0);
        });
    }
}
