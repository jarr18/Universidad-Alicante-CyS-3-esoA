package cliente.gui;

import cliente.ClienteServicio;

import javax.swing.*;
import java.awt.*;

/** Pantalla de acceso: inicio de sesion (con 2FA si esta activado) y alta de usuarios. */
public class VentanaLogin extends JFrame {

    private final JTextField txtServidor = new JTextField(System.getProperty("cys.servidor", "https://localhost:8443"), 24);
    private final JTextField txtUsuario = new JTextField(24);
    private final JPasswordField txtPassword = new JPasswordField(24);
    private final JButton btnEntrar = new JButton("Iniciar sesión");
    private final JButton btnCrear = new JButton("Crear cuenta");
    private final JLabel lblEstado = new JLabel(" ");

    public VentanaLogin() {
        super("Servicio seguro de contenidos multimedia");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(18, 22, 14, 22));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(5, 5, 5, 5);
        g.fill = GridBagConstraints.HORIZONTAL;
        JLabel titulo = new JLabel("Acceso al servicio seguro");
        titulo.setFont(titulo.getFont().deriveFont(Font.BOLD, 18f));
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        p.add(titulo, g);
        g.gridwidth = 1;
        fila(p, g, 1, "Servidor", txtServidor);
        fila(p, g, 2, "Usuario", txtUsuario);
        fila(p, g, 3, "Contraseña", txtPassword);
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(btnCrear);
        botones.add(btnEntrar);
        g.gridx = 0; g.gridy = 4; g.gridwidth = 2;
        p.add(botones, g);
        g.gridy = 5;
        lblEstado.setForeground(Color.GRAY);
        p.add(lblEstado, g);
        setContentPane(p);
        getRootPane().setDefaultButton(btnEntrar);
        btnEntrar.addActionListener(e -> entrar());
        btnCrear.addActionListener(e -> crear());
        pack();
        setResizable(false);
        setLocationRelativeTo(null);
    }

    private static void fila(JPanel p, GridBagConstraints g, int y, String texto, JComponent c) {
        g.gridx = 0; g.gridy = y; g.weightx = 0;
        p.add(new JLabel(texto), g);
        g.gridx = 1; g.weightx = 1;
        p.add(c, g);
    }

    private void ocupado(boolean si, String msg) {
        btnEntrar.setEnabled(!si);
        btnCrear.setEnabled(!si);
        lblEstado.setText(msg);
        setCursor(si ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
    }

    private void entrar() {
        String usuario = txtUsuario.getText().trim();
        String password = new String(txtPassword.getPassword());
        if (usuario.isEmpty() || password.isEmpty()) {
            lblEstado.setText("Escribe usuario y contraseña.");
            return;
        }
        ClienteServicio servicio = new ClienteServicio(txtServidor.getText());
        ocupado(true, "Derivando claves y autenticando…");
        Ayuda.segundoPlano(() -> servicio.iniciarSesion(usuario, password), requiere2fa -> {
            ocupado(false, " ");
            if (!requiere2fa) {
                abrir(servicio);
                return;
            }
            pedirCodigo(servicio);
        }, t -> {
            ocupado(false, " ");
            Ayuda.error(this, t);
        });
    }

    private void pedirCodigo(ClienteServicio servicio) {
        String codigo = JOptionPane.showInputDialog(this,
                "Introduce el código de 6 dígitos de tu aplicación de autenticación:", "Segundo factor (2FA)",
                JOptionPane.QUESTION_MESSAGE);
        if (codigo == null) {
            Ayuda.segundoPlano(() -> { servicio.cerrarSesion(); return null; }, x -> { }, x -> { });
            return;
        }
        ocupado(true, "Comprobando código…");
        Ayuda.segundoPlano(() -> { servicio.completar2fa(codigo.trim()); return null; }, x -> {
            ocupado(false, " ");
            abrir(servicio);
        }, t -> {
            ocupado(false, " ");
            Ayuda.error(this, t);
        });
    }

    private void abrir(ClienteServicio servicio) {
        txtPassword.setText("");
        new VentanaPrincipal(servicio).setVisible(true);
        dispose();
    }

    private void crear() {
        String usuario = txtUsuario.getText().trim();
        String password = new String(txtPassword.getPassword());
        if (usuario.isEmpty() || password.isEmpty()) {
            lblEstado.setText("Escribe el usuario y la contraseña que quieres usar.");
            return;
        }
        ClienteServicio servicio = new ClienteServicio(txtServidor.getText());
        ocupado(true, "Generando claves RSA y registrando…");
        Ayuda.segundoPlano(() -> { servicio.registrar(usuario, password); return null; }, x -> {
            ocupado(false, " ");
            JOptionPane.showMessageDialog(this, "Cuenta «" + usuario + "» creada. Ya puedes iniciar sesión.",
                    "Cuenta creada", JOptionPane.INFORMATION_MESSAGE);
        }, t -> {
            ocupado(false, " ");
            Ayuda.error(this, t);
        });
    }
}
