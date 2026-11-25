package cliente.gui;

import cliente.ClienteServicio;

import javax.swing.*;
import java.awt.Component;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** Utilidades de interfaz: tareas en segundo plano y formato de datos. */
final class Ayuda {

    private Ayuda() {
    }

    /** Ejecuta la tarea fuera del hilo de Swing y devuelve el resultado o el error en el hilo de Swing. */
    static <T> void segundoPlano(Callable<T> tarea, Consumer<T> alTerminar, Consumer<Throwable> alFallar) {
        new SwingWorker<T, Void>() {
            @Override
            protected T doInBackground() throws Exception {
                return tarea.call();
            }

            @Override
            protected void done() {
                try {
                    alTerminar.accept(get());
                } catch (java.util.concurrent.ExecutionException e) {
                    alFallar.accept(e.getCause() != null ? e.getCause() : e);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }.execute();
    }

    static void error(Component padre, Throwable t) {
        JOptionPane.showMessageDialog(padre, ClienteServicio.mensaje(t), "Error", JOptionPane.ERROR_MESSAGE);
    }

    static String tamano(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double v = bytes / 1024.0;
        String[] u = {"KB", "MB", "GB"};
        int i = 0;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format("%.1f %s", v, u[i]);
    }

    static String fecha(long ms) {
        return new java.text.SimpleDateFormat("dd/MM/yyyy HH:mm").format(new java.util.Date(ms));
    }
}
