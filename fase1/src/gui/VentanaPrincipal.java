package gui;

import model.ArchivoCifrado;
import service.CifradoService;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * Interfaz grafica sencilla (Swing, sin librerias externas).
 * Dos pantallas: login (usuario unico + password) y gestion de archivos cifrados.
 * Toda la logica esta en CifradoService; aqui solo hay interfaz.
 * Las operaciones lentas (RSA, cifrar ficheros) se ejecutan en segundo
 * plano con SwingWorker para no congelar la ventana.
 */
public class VentanaPrincipal extends JFrame {

    private static final String PANTALLA_LOGIN = "login";
    private static final String PANTALLA_ARCHIVOS = "archivos";

    private final CifradoService servicio;
    private final CardLayout pantallas = new CardLayout();
    private final JPanel raiz = new JPanel(pantallas);

    // Pantalla de login
    private final JTextField txtUsuario = new JTextField(18);
    private final JPasswordField txtPassword = new JPasswordField(18);
    private final JButton btnEntrar = new JButton("Iniciar sesión");

    // Pantalla de archivos
    private final JLabel lblSesion = new JLabel();
    private final DefaultTableModel modelo = new DefaultTableModel(
            new String[]{"Id", "Archivo original", "Fichero cifrado"}, 0) {
        @Override public boolean isCellEditable(int fila, int col) { return false; }
    };
    private final JTable tabla = new JTable(modelo);
    private final JButton btnCifrar = new JButton("Cifrar archivo(s)…");
    private final JButton btnDescifrar = new JButton("Descifrar seleccionado");
    private final JButton btnActualizar = new JButton("Actualizar");
    private final JButton btnSalir = new JButton("Cerrar sesión");
    private final JLabel lblEstado = new JLabel(" ");

    private final JButton[] botones = {btnEntrar, btnCifrar, btnDescifrar, btnActualizar, btnSalir};

    public VentanaPrincipal(CifradoService servicio) {
        super("Servicio seguro de contenidos multimedia — Fase I");
        this.servicio = servicio;

        raiz.add(construirLogin(), PANTALLA_LOGIN);
        raiz.add(construirArchivos(), PANTALLA_ARCHIVOS);
        add(raiz);

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(680, 440);
        setMinimumSize(new Dimension(560, 360));
        setLocationRelativeTo(null);
        mostrarLogin();
    }

    // ---------------------------------------------------------------
    // Construccion de las pantallas
    // ---------------------------------------------------------------

    private JPanel construirLogin() {
        JPanel centro = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6, 6, 6, 6);
        g.fill = GridBagConstraints.HORIZONTAL;

        JLabel titulo = new JLabel("Acceso al servicio seguro", SwingConstants.CENTER);
        titulo.setFont(titulo.getFont().deriveFont(Font.BOLD, 18f));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        centro.add(titulo, g);

        g.gridwidth = 1; g.gridy = 1; g.gridx = 0;
        centro.add(new JLabel("Usuario:"), g);
        g.gridx = 1;
        centro.add(txtUsuario, g);

        g.gridy = 2; g.gridx = 0;
        centro.add(new JLabel("Password:"), g);
        g.gridx = 1;
        centro.add(txtPassword, g);

        g.gridy = 3; g.gridx = 0; g.gridwidth = 2;
        centro.add(btnEntrar, g);

        btnEntrar.addActionListener(e -> iniciarSesion());

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));
        panel.add(centro, BorderLayout.CENTER);
        return panel;
    }

    private JPanel construirArchivos() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(new EmptyBorder(12, 12, 12, 12));

        JPanel cabecera = new JPanel(new BorderLayout());
        lblSesion.setFont(lblSesion.getFont().deriveFont(Font.BOLD, 14f));
        cabecera.add(lblSesion, BorderLayout.WEST);
        cabecera.add(btnSalir, BorderLayout.EAST);
        panel.add(cabecera, BorderLayout.NORTH);

        tabla.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tabla.setRowHeight(24);
        tabla.getColumnModel().getColumn(0).setMaxWidth(50);
        tabla.getSelectionModel().addListSelectionListener(e -> actualizarBotones());
        panel.add(new JScrollPane(tabla), BorderLayout.CENTER);

        JPanel sur = new JPanel(new BorderLayout(0, 6));
        JPanel acciones = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        acciones.add(btnCifrar);
        acciones.add(btnDescifrar);
        acciones.add(btnActualizar);
        sur.add(acciones, BorderLayout.NORTH);
        sur.add(lblEstado, BorderLayout.SOUTH);
        panel.add(sur, BorderLayout.SOUTH);

        btnCifrar.addActionListener(e -> cifrar());
        btnDescifrar.addActionListener(e -> descifrar());
        btnActualizar.addActionListener(e -> refrescar());
        btnSalir.addActionListener(e -> cerrarSesion());
        return panel;
    }

    // ---------------------------------------------------------------
    // Navegacion entre pantallas
    // ---------------------------------------------------------------

    private void mostrarLogin() {
        txtPassword.setText("");
        pantallas.show(raiz, PANTALLA_LOGIN);
        getRootPane().setDefaultButton(btnEntrar);
        txtUsuario.requestFocusInWindow();
    }

    private void mostrarArchivos() {
        lblSesion.setText("Sesión: " + servicio.getNombreUsuario());
        modelo.setRowCount(0);
        setEstado(" ");
        pantallas.show(raiz, PANTALLA_ARCHIVOS);
        getRootPane().setDefaultButton(null);
        actualizarBotones();
        refrescar();
    }

    // ---------------------------------------------------------------
    // Acciones: sesion
    // ---------------------------------------------------------------

    private void iniciarSesion() {
        String usuario = txtUsuario.getText().trim();
        String password = new String(txtPassword.getPassword());
        ejecutar("Iniciando sesión…", () -> {
            servicio.iniciarSesion(usuario, password);
            return null;
        }, r -> mostrarArchivos());
    }

    private void cerrarSesion() {
        servicio.cerrarSesion();
        modelo.setRowCount(0);
        mostrarLogin();
    }

    // ---------------------------------------------------------------
    // Acciones: archivos
    // ---------------------------------------------------------------

    private void refrescar() {
        ejecutar("Cargando archivos…", servicio::listar, this::rellenarTabla);
    }

    private void rellenarTabla(List<ArchivoCifrado> archivos) {
        modelo.setRowCount(0);
        for (ArchivoCifrado a : archivos) {
            modelo.addRow(new Object[]{a.getId(), a.getNombreOriginal(), a.getRutaCifrado()});
        }
        setEstado(archivos.isEmpty() ? "No tienes archivos cifrados." : archivos.size() + " archivo(s) cifrado(s).");
    }

    private void cifrar() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Elige los archivos a cifrar");
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setMultiSelectionEnabled(true);
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        java.io.File[] elegidos = fc.getSelectedFiles();
        if (elegidos.length == 0) return;

        int ok = JOptionPane.showConfirmDialog(this,
                "Se cifrarán " + elegidos.length + " archivo(s) y los originales se ELIMINARÁN,\n"
                        + "quedando solo la versión cifrada (.enc) en la misma carpeta.\n\n¿Continuar?",
                "Confirmar cifrado", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.YES_OPTION) return;

        ejecutar("Cifrando…", () -> {
            int correctos = 0;
            StringBuilder fallos = new StringBuilder();
            for (java.io.File f : elegidos) {
                try {
                    servicio.cifrar(f.toPath());
                    correctos++;
                } catch (Exception ex) {
                    fallos.append("• ").append(f.getName()).append(": ").append(mensaje(ex)).append('\n');
                }
            }
            return new Object[]{correctos, fallos.toString()};
        }, r -> {
            int correctos = (int) r[0];
            String fallos = (String) r[1];
            refrescar();
            setEstado(correctos + " archivo(s) cifrado(s).");
            if (!fallos.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No se pudieron cifrar:\n" + fallos,
                        "Algunos archivos fallaron", JOptionPane.WARNING_MESSAGE);
            }
        });
    }

    private void descifrar() {
        int fila = tabla.getSelectedRow();
        if (fila < 0) return;
        int id = (int) modelo.getValueAt(fila, 0);
        String nombre = (String) modelo.getValueAt(fila, 1);

        String[] opciones = {"Misma carpeta", "Elegir carpeta…", "Cancelar"};
        int eleccion = JOptionPane.showOptionDialog(this,
                "Se restaurará «" + nombre + "».\n"
                        + "El .enc y su clave se eliminarán: para volver a descifrarlo\n"
                        + "tendrás que cifrarlo de nuevo.\n\n¿Dónde quieres restaurarlo?",
                "Descifrar archivo", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, opciones, opciones[0]);

        Path carpeta = null;
        if (eleccion == 1) {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Carpeta de destino");
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            carpeta = fc.getSelectedFile().toPath();
        } else if (eleccion != 0) {
            return;   // Cancelar o cerrar el dialogo
        }

        Path destinoCarpeta = carpeta;
        ejecutar("Descifrando…", () -> servicio.descifrar(id, destinoCarpeta), restaurado -> {
            refrescar();
            setEstado("Restaurado en " + restaurado);
            JOptionPane.showMessageDialog(this, "Archivo restaurado en:\n" + restaurado,
                    "Descifrado correcto", JOptionPane.INFORMATION_MESSAGE);
        });
    }

    // ---------------------------------------------------------------
    // Utilidades de interfaz
    // ---------------------------------------------------------------

    /** Ejecuta la tarea en segundo plano, bloquea los botones mientras tanto y muestra errores. */
    private <T> void ejecutar(String mensajeOcupado, Callable<T> tarea, Consumer<T> alTerminar) {
        setOcupado(true, mensajeOcupado);
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception {
                return tarea.call();
            }
            @Override protected void done() {
                setOcupado(false, null);
                try {
                    alTerminar.accept(get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ExecutionException e) {
                    setEstado(" ");
                    JOptionPane.showMessageDialog(VentanaPrincipal.this, mensaje(e.getCause()),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void setOcupado(boolean ocupado, String mensaje) {
        setCursor(ocupado ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
        for (JButton b : botones) b.setEnabled(!ocupado);
        if (ocupado) {
            setEstado(mensaje);
        } else {
            actualizarBotones();
        }
    }

    /** "Descifrar" solo tiene sentido con una fila seleccionada. */
    private void actualizarBotones() {
        btnDescifrar.setEnabled(tabla.getSelectedRow() >= 0 && btnCifrar.isEnabled());
    }

    private void setEstado(String texto) {
        lblEstado.setText(texto == null || texto.isEmpty() ? " " : texto);
    }

    private static String mensaje(Throwable t) {
        String m = t.getMessage();
        return (m == null || m.isBlank()) ? t.getClass().getSimpleName() : m;
    }
}
