package comun;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JSON minimo (sin librerias externas) compartido por cliente y servidor.
 * Tipos: Map&lt;String,Object&gt;, List&lt;Object&gt;, String, Long, Double, Boolean y null.
 */
public final class Json {

    private Json() {
    }

    public static class JsonException extends RuntimeException {
        public JsonException(String m) {
            super(m);
        }
    }

    // ------------------------------------------------------------ lectura

    public static Object parse(String texto) {
        Lector l = new Lector(texto);
        l.blancos();
        Object v = l.valor();
        l.blancos();
        if (l.i != texto.length()) throw new JsonException("Texto sobrante tras el JSON");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObjeto(String texto) {
        Object o = parse(texto);
        if (!(o instanceof Map)) throw new JsonException("Se esperaba un objeto JSON");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> parseLista(String texto) {
        Object o = parse(texto);
        if (!(o instanceof List)) throw new JsonException("Se esperaba una lista JSON");
        return (List<Object>) o;
    }

    private static final class Lector {
        final String s;
        int i = 0;

        Lector(String s) {
            this.s = s;
        }

        void blancos() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        char ver() {
            if (i >= s.length()) throw new JsonException("Fin inesperado del JSON");
            return s.charAt(i);
        }

        void esperar(char c) {
            if (ver() != c) throw new JsonException("Se esperaba '" + c + "' en la posicion " + i);
            i++;
        }

        Object valor() {
            blancos();
            char c = ver();
            if (c == '{') return objeto();
            if (c == '[') return lista();
            if (c == '"') return cadena();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            return numero();
        }

        Map<String, Object> objeto() {
            Map<String, Object> m = new LinkedHashMap<>();
            esperar('{');
            blancos();
            if (ver() == '}') { i++; return m; }
            while (true) {
                blancos();
                String k = cadena();
                blancos();
                esperar(':');
                m.put(k, valor());
                blancos();
                char c = ver();
                i++;
                if (c == '}') return m;
                if (c != ',') throw new JsonException("Se esperaba ',' o '}' en la posicion " + (i - 1));
            }
        }

        List<Object> lista() {
            List<Object> l = new ArrayList<>();
            esperar('[');
            blancos();
            if (ver() == ']') { i++; return l; }
            while (true) {
                l.add(valor());
                blancos();
                char c = ver();
                i++;
                if (c == ']') return l;
                if (c != ',') throw new JsonException("Se esperaba ',' o ']' en la posicion " + (i - 1));
            }
        }

        String cadena() {
            esperar('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = ver();
                i++;
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                char e = ver();
                i++;
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length()) throw new JsonException("Escape \\u incompleto");
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw new JsonException("Escape no valido: \\" + e);
                }
            }
        }

        Object numero() {
            int ini = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
            String t = s.substring(ini, i);
            if (t.isEmpty()) throw new JsonException("Valor no valido en la posicion " + ini);
            try {
                if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
                return Long.parseLong(t);
            } catch (NumberFormatException ex) {
                throw new JsonException("Numero no valido: " + t);
            }
        }
    }

    // ----------------------------------------------------------- escritura

    public static String texto(Object o) {
        StringBuilder sb = new StringBuilder();
        escribir(sb, o);
        return sb.toString();
    }

    private static void escribir(StringBuilder sb, Object o) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String s) {
            cadena(sb, s);
        } else if (o instanceof Boolean || o instanceof Long || o instanceof Integer) {
            sb.append(o);
        } else if (o instanceof Number n) {
            sb.append(n.doubleValue());
        } else if (o instanceof Map<?, ?> m) {
            sb.append('{');
            boolean primero = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!primero) sb.append(',');
                primero = false;
                cadena(sb, String.valueOf(e.getKey()));
                sb.append(':');
                escribir(sb, e.getValue());
            }
            sb.append('}');
        } else if (o instanceof Iterable<?> it) {
            sb.append('[');
            boolean primero = true;
            for (Object x : it) {
                if (!primero) sb.append(',');
                primero = false;
                escribir(sb, x);
            }
            sb.append(']');
        } else {
            throw new JsonException("Tipo no soportado: " + o.getClass());
        }
    }

    private static void cadena(StringBuilder sb, String s) {
        sb.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    // ------------------------------------------------- ayudas de acceso

    public static String str(Map<String, Object> m, String clave) {
        Object v = m.get(clave);
        return v instanceof String s ? s : null;
    }

    public static long num(Map<String, Object> m, String clave, long porDefecto) {
        Object v = m.get(clave);
        return v instanceof Number n ? n.longValue() : porDefecto;
    }

    public static boolean bool(Map<String, Object> m, String clave) {
        return Boolean.TRUE.equals(m.get(clave));
    }

    /** Construye un objeto a partir de pares clave, valor, clave, valor... */
    public static Map<String, Object> obj(Object... pares) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k + 1 < pares.length; k += 2) m.put((String) pares[k], pares[k + 1]);
        return m;
    }
}
