package sh.testssl.wdneo.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HTTP transport for the WD NEO API, plain Java only.
 *
 * Deliberately free of android.* so the identical class can be unit-tested on a
 * desktop JVM against the real backend. The Android app supplies an
 * {@link Transport}; the desktop harness supplies one backed by HttpURLConnection
 * too, so what is tested is what ships.
 */
public final class HttpClient {

    public static final Charset UTF8 = Charset.forName("UTF-8");

    /** One HTTP response: status code, body text, and content type. */
    public static final class Response {
        public final int status;
        public final String body;
        public final String contentType;

        Response(int status, String body, String contentType) {
            this.status = status;
            this.body = body == null ? "" : body;
            this.contentType = contentType == null ? "" : contentType;
        }

        public boolean ok() { return status >= 200 && status < 300; }

        public boolean isJson() { return contentType.contains("json"); }

        /** The server's error message, when the body is JSON {detail: ...}. */
        public String errorMessage() {
            try {
                Map<String, Object> o = Json.parseObject(body);
                Object d = o.get("detail");
                if (d instanceof String) return (String) d;
                if (d instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> dm = (Map<String, Object>) d;
                    String msg = Json.str(dm, "message");
                    String code = Json.str(dm, "code");
                    if (!msg.isEmpty() && !code.isEmpty()) return code + ": " + msg;
                    if (!msg.isEmpty()) return msg;
                    if (!code.isEmpty()) return code;
                }
                if (d != null) return String.valueOf(d);
            } catch (Json.JsonException ignored) {
                // non-JSON error body; fall through
            }
            String t = body.trim();
            if (t.length() > 300) t = t.substring(0, 300) + "...";
            return t.isEmpty() ? ("HTTP " + status) : t;
        }
    }

    /** Pluggable transport so the wrapper is testable and reusable. */
    public interface Transport {
        Response send(String method, String url, Map<String, String> headers, byte[] body,
                      int connectTimeoutMs, int readTimeoutMs) throws IOException;
    }

    private final String baseUrl;
    private final Transport transport;
    private String token = "";
    private int connectTimeoutMs = 15000;
    private int readTimeoutMs = 60000;

    public HttpClient(String baseUrl, Transport transport) {
        this.baseUrl = normalizeBase(baseUrl);
        this.transport = transport;
    }

    /** Trim trailing slashes and add a scheme when the user omitted one. */
    public static String normalizeBase(String raw) {
        String b = raw == null ? "" : raw.trim();
        if (b.isEmpty()) return "";
        if (!b.startsWith("http://") && !b.startsWith("https://")) b = "http://" + b;
        while (b.endsWith("/")) b = b.substring(0, b.length() - 1);
        return b;
    }

    public String baseUrl() { return baseUrl; }

    public void setToken(String token) { this.token = token == null ? "" : token; }

    public String token() { return token; }

    public boolean hasToken() { return !token.isEmpty(); }

    public void setTimeouts(int connectMs, int readMs) {
        this.connectTimeoutMs = connectMs;
        this.readTimeoutMs = readMs;
    }

    // ------------------------------------------------------------- primitives

    public Response get(String path) throws IOException {
        return request("GET", path, null, null);
    }

    public Response post(String path, String jsonBody) throws IOException {
        return request("POST", path, jsonBody, "application/json; charset=utf-8");
    }

    /** POST with an explicit string body and content type. */
    public Response postRaw(String path, String body, String contentType) throws IOException {
        return request("POST", path, body, contentType);
    }

    public Response delete(String path) throws IOException {
        return request("DELETE", path, null, null);
    }

    private Response request(String method, String path, String body, String contentType)
            throws IOException {
        if (baseUrl.isEmpty()) throw new IOException("no server URL configured");
        String url = path.startsWith("http") ? path : baseUrl + path;
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("accept", "application/json");
        headers.put("user-agent", "WD-NEO-Android/1.0");
        if (!token.isEmpty()) headers.put("authorization", "Bearer " + token);
        if (contentType != null) headers.put("content-type", contentType);
        byte[] payload = body == null ? null : body.getBytes(UTF8);
        return transport.send(method, url, headers, payload, connectTimeoutMs, readTimeoutMs);
    }

    // --------------------------------------------------------------- API call

    /**
     * Perform a JSON API call and parse the response.
     *
     * @throws ApiException when the transport fails or the status is not 2xx,
     *                      carrying the server's own message where available.
     */
    public Map<String, Object> call(String method, String path, Map<String, Object> body)
            throws ApiException {
        String json = body == null ? null : Json.write(body);
        Response r;
        try {
            r = request(method, path, json,
                    json == null ? null : "application/json; charset=utf-8");
        } catch (IOException e) {
            throw new ApiException("network error: " + e.getMessage(), 0, e);
        }
        if (!r.ok()) {
            throw new ApiException(r.errorMessage(), r.status, null);
        }
        if (r.body.trim().isEmpty()) {
            return new LinkedHashMap<String, Object>();
        }
        try {
            return Json.parseObject(r.body);
        } catch (Json.JsonException e) {
            throw new ApiException("invalid JSON from server: " + e.getMessage(), r.status, e);
        }
    }

    public Map<String, Object> getJson(String path) throws ApiException {
        return call("GET", path, null);
    }

    public Map<String, Object> postJson(String path, Map<String, Object> body) throws ApiException {
        return call("POST", path, body);
    }

    /** Fetch a non-JSON resource (a report) as bytes. */
    public byte[] getBytes(String path) throws ApiException {
        try {
            Response r = request("GET", path, null, null);
            if (!r.ok()) throw new ApiException(r.errorMessage(), r.status, null);
            return r.body.getBytes(UTF8);
        } catch (IOException e) {
            throw new ApiException("network error: " + e.getMessage(), 0, e);
        }
    }

    // ---------------------------------------------------------------- default

    /** A transport backed by {@link HttpURLConnection}, usable on JVM and Android. */
    public static Transport defaultTransport() {
        return new Transport() {
            @Override
            public Response send(String method, String url, Map<String, String> headers,
                                 byte[] body, int connectTimeoutMs, int readTimeoutMs)
                    throws IOException {
                HttpURLConnection c = null;
                try {
                    c = (HttpURLConnection) new URL(url).openConnection();
                    c.setRequestMethod(method);
                    c.setConnectTimeout(connectTimeoutMs);
                    c.setReadTimeout(readTimeoutMs);
                    c.setInstanceFollowRedirects(true);
                    for (Map.Entry<String, String> h : headers.entrySet()) {
                        c.setRequestProperty(h.getKey(), h.getValue());
                    }
                    if (body != null) {
                        c.setDoOutput(true);
                        c.setFixedLengthStreamingMode(body.length);
                        OutputStream os = c.getOutputStream();
                        try { os.write(body); } finally { os.close(); }
                    }
                    int status = c.getResponseCode();
                    InputStream is = status >= 400 ? c.getErrorStream() : c.getInputStream();
                    String text = readAll(is);
                    String ctype = c.getHeaderField("content-type");
                    return new Response(status, text, ctype);
                } finally {
                    if (c != null) c.disconnect();
                }
            }
        };
    }

    private static String readAll(InputStream is) throws IOException {
        if (is == null) return "";
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            return new String(bos.toByteArray(), UTF8);
        } finally {
            is.close();
        }
    }

    /** Error carrying the HTTP status so callers can special-case 401/403/423. */
    public static final class ApiException extends Exception {
        public final int status;

        public ApiException(String message, int status, Throwable cause) {
            super(message, cause);
            this.status = status;
        }
    }
}
