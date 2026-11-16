package sh.testssl.wdneo.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON reader/writer.
 *
 * Written in plain Java (no android.* and no org.json) so the exact same code
 * that ships inside the APK can also be compiled and exercised on a desktop JVM
 * by the test harness. That is what makes the client verifiable without an
 * emulator.
 *
 * Supports the whole JSON grammar: objects, arrays, strings with all escapes
 * (including \\uXXXX surrogate pairs), numbers, true/false/null.
 *
 * Values map to: Map&lt;String,Object&gt;, List&lt;Object&gt;, String, Double, Long,
 * Boolean, null.
 */
public final class Json {

    private Json() {}

    // ------------------------------------------------------------------ parse

    public static Object parse(String text) throws JsonException {
        if (text == null) throw new JsonException("null input");
        Parser p = new Parser(text);
        p.skipWs();
        Object v = p.value();
        p.skipWs();
        if (!p.eof()) throw new JsonException("trailing data at offset " + p.pos);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) throws JsonException {
        Object v = parse(text);
        if (!(v instanceof Map)) throw new JsonException("expected a JSON object");
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> parseArray(String text) throws JsonException {
        Object v = parse(text);
        if (!(v instanceof List)) throw new JsonException("expected a JSON array");
        return (List<Object>) v;
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) { this.s = s; }

        boolean eof() { return pos >= s.length(); }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        Object value() throws JsonException {
            if (eof()) throw new JsonException("unexpected end of input");
            char c = s.charAt(pos);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return number();
                    throw new JsonException("unexpected character '" + c + "' at " + pos);
            }
        }

        private void expect(String lit) throws JsonException {
            if (!s.startsWith(lit, pos)) throw new JsonException("expected '" + lit + "' at " + pos);
            pos += lit.length();
        }

        private Map<String, Object> object() throws JsonException {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            pos++; // '{
            skipWs();
            if (!eof() && s.charAt(pos) == '}') { pos++; return out; }
            while (true) {
                skipWs();
                if (eof() || s.charAt(pos) != '"') throw new JsonException("expected key at " + pos);
                String key = string();
                skipWs();
                if (eof() || s.charAt(pos) != ':') throw new JsonException("expected ':' at " + pos);
                pos++;
                skipWs();
                out.put(key, value());
                skipWs();
                if (eof()) throw new JsonException("unterminated object");
                char c = s.charAt(pos);
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; return out; }
                throw new JsonException("expected ',' or '}' at " + pos);
            }
        }

        private List<Object> array() throws JsonException {
            List<Object> out = new ArrayList<Object>();
            pos++; // '['
            skipWs();
            if (!eof() && s.charAt(pos) == ']') { pos++; return out; }
            while (true) {
                skipWs();
                out.add(value());
                skipWs();
                if (eof()) throw new JsonException("unterminated array");
                char c = s.charAt(pos);
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; return out; }
                throw new JsonException("expected ',' or ']' at " + pos);
            }
        }

        private String string() throws JsonException {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (eof()) throw new JsonException("unterminated string");
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c != '\\') { sb.append(c); continue; }
                if (eof()) throw new JsonException("unterminated escape");
                char e = s.charAt(pos++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (pos + 4 > s.length()) throw new JsonException("bad \\u escape");
                        String hex = s.substring(pos, pos + 4);
                        pos += 4;
                        try {
                            sb.append((char) Integer.parseInt(hex, 16));
                        } catch (NumberFormatException ex) {
                            throw new JsonException("bad \\u escape: " + hex);
                        }
                        break;
                    default:
                        throw new JsonException("bad escape \\" + e);
                }
            }
        }

        private Object number() throws JsonException {
            int start = pos;
            if (!eof() && s.charAt(pos) == '-') pos++;
            while (!eof() && Character.isDigit(s.charAt(pos))) pos++;
            boolean fractional = false;
            if (!eof() && s.charAt(pos) == '.') {
                fractional = true; pos++;
                while (!eof() && Character.isDigit(s.charAt(pos))) pos++;
            }
            if (!eof() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                fractional = true; pos++;
                if (!eof() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                while (!eof() && Character.isDigit(s.charAt(pos))) pos++;
            }
            String raw = s.substring(start, pos);
            try {
                if (fractional) return Double.valueOf(raw);
                long l = Long.parseLong(raw);
                if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return Integer.valueOf((int) l);
                return Long.valueOf(l);
            } catch (NumberFormatException ex) {
                throw new JsonException("bad number: " + raw);
            }
        }
    }

    // -------------------------------------------------------------------- write

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { writeString(sb, (String) v); return; }
        if (v instanceof Boolean) { sb.append(v.toString()); return; }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (d == Math.rint(d) && !Double.isInfinite(d)) sb.append((long) d);
            else sb.append(d);
            return;
        }
        if (v instanceof Number) { sb.append(v.toString()); return; }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, e.getKey());
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                writeValue(sb, o);
            }
            sb.append(']');
            return;
        }
        writeString(sb, v.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    // -------------------------------------------------------------- accessors

    /** Read a nested string, returning "" when absent. */
    @SuppressWarnings("unchecked")
    public static String str(Map<String, Object> o, String key) {
        Object v = o == null ? null : o.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    /** Read a nested number as Double, or null. */
    @SuppressWarnings("unchecked")
    public static Double num(Map<String, Object> o, String key) {
        Object v = o == null ? null : o.get(key);
        if (v instanceof Number) return ((Number) v).doubleValue();
        return null;
    }

    /** Read a nested boolean, defaulting to false. */
    @SuppressWarnings("unchecked")
    public static boolean bool(Map<String, Object> o, String key) {
        Object v = o == null ? null : o.get(key);
        return v instanceof Boolean && (Boolean) v;
    }

    /** Read a nested object, or an empty map. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> o, String key) {
        Object v = o == null ? null : o.get(key);
        if (v instanceof Map) return (Map<String, Object>) v;
        return new LinkedHashMap<String, Object>();
    }

    /** Read a nested list, or an empty list. */
    @SuppressWarnings("unchecked")
    public static List<Object> arr(Map<String, Object> o, String key) {
        Object v = o == null ? null : o.get(key);
        if (v instanceof List) return (List<Object>) v;
        return new ArrayList<Object>();
    }

    public static final class JsonException extends Exception {
        public JsonException(String message) { super(message); }
    }
}
