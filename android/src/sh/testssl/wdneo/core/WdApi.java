package sh.testssl.wdneo.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed facade over the WD NEO REST API.
 *
 * Every method mirrors a real endpoint, so a client-side bug is either a wrong
 * path, a wrong body, or a wrong field name - all of which the JVM harness
 * catches by calling the live server.
 */
public final class WdApi {

    private final HttpClient http;

    public WdApi(String baseUrl) {
        this(new HttpClient(baseUrl, HttpClient.defaultTransport()));
    }

    public WdApi(HttpClient http) { this.http = http; }

    public HttpClient http() { return http; }

    public String baseUrl() { return http.baseUrl(); }

    public boolean authenticated() { return http.hasToken(); }

    public void setToken(String token) { http.setToken(token); }

    // ------------------------------------------------------------- public ----

    /** GET /api/health - also used to validate a server URL before login. */
    public Map<String, Object> health() throws HttpClient.ApiException {
        return http.getJson("/api/health");
    }

    public Map<String, Object> version() throws HttpClient.ApiException {
        return http.getJson("/api/version");
    }

    public Map<String, Object> capabilities() throws HttpClient.ApiException {
        return http.getJson("/api/capabilities");
    }

    // --------------------------------------------------------------- auth ----

    /** POST /api/auth/stage1 - WD shortcut + operator password. */
    public Map<String, Object> stage1(String username, String password, String shortcut)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("username", username);
        body.put("password", password);
        body.put("shortcut", shortcut);
        Map<String, Object> r = http.postJson("/api/auth/stage1", body);
        String token = Json.str(r, "token");
        if (token.isEmpty()) throw new HttpClient.ApiException("stage 1 returned no token", 200, null);
        http.setToken(token);
        return r;
    }

    /** POST /api/auth/stage2 - the separate PIN.
     *
     * On a stage-2 failure the server keeps the stage-1 session valid, so the
     * bearer is deliberately retained for a retry.
     */
    public Map<String, Object> stage2(String pin) throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("pin", pin);
        return http.postJson("/api/auth/stage2", body);
    }

    public Map<String, Object> me() throws HttpClient.ApiException {
        return http.getJson("/api/auth/me");
    }

    /** The operator's current stage (1 or 2); 0 when unauthenticated. */
    public int stage() throws HttpClient.ApiException {
        Map<String, Object> r = me();
        Double s = Json.num(r, "stage");
        return s == null ? 0 : s.intValue();
    }

    public Map<String, Object> logout() throws HttpClient.ApiException {
        try {
            return http.postJson("/api/auth/logout", new LinkedHashMap<String, Object>());
        } finally {
            http.setToken("");
        }
    }

    public Map<String, Object> changePassword(String oldPassword, String newPassword)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("old_password", oldPassword);
        body.put("new_password", newPassword);
        return http.postJson("/api/auth/password", body);
    }

    public Map<String, Object> changePin(String password, String newPin)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("password", password);
        body.put("new_pin", newPin);
        return http.postJson("/api/auth/pin", body);
    }

    // -------------------------------------------------------------- scope ----

    public List<Object> scope() throws HttpClient.ApiException {
        return Json.arr(http.getJson("/api/scope"), "scope");
    }

    public Map<String, Object> addScope(String target, String description)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("target", target);
        body.put("description", description == null ? "" : description);
        return http.postJson("/api/scope", body);
    }

    public Map<String, Object> removeScope(String id) throws HttpClient.ApiException {
        return http.call("DELETE", "/api/scope/" + id, null);
    }

    /** POST /api/scope/validate - per-target in-scope verdict. */
    public Map<String, Object> validateScope(List<String> targets) throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("targets", new ArrayList<Object>(targets));
        return http.postJson("/api/scope/validate", body);
    }

    // ---------------------------------------------------------- templates ----

    public List<Object> templates() throws HttpClient.ApiException {
        return Json.arr(http.getJson("/api/templates"), "templates");
    }

    public Map<String, Object> template(String id) throws HttpClient.ApiException {
        return http.getJson("/api/templates/" + id);
    }

    public Map<String, Object> modules() throws HttpClient.ApiException {
        return http.getJson("/api/modules");
    }

    // -------------------------------------------------------- assessments ----

    /** POST /api/authorizations - must precede any execution. */
    public Map<String, Object> authorize(List<String> targets, int ttlMinutes, String note)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("targets", new ArrayList<Object>(targets));
        body.put("ttl_minutes", Integer.valueOf(ttlMinutes));
        body.put("note", note == null ? "" : note);
        body.put("intended_test", note == null ? "" : note);
        return http.postJson("/api/authorizations", body);
    }

    public Map<String, Object> createAssessment(String template, List<String> targets,
                                                String mode, String intensity,
                                                Map<String, Object> params)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("template", template);
        body.put("targets", new ArrayList<Object>(targets));
        body.put("mode", mode);
        body.put("intensity", intensity);
        body.put("params", params == null ? new LinkedHashMap<String, Object>() : params);
        return http.postJson("/api/assessments", body);
    }

    /** POST /api/assessments/{id}/run - requires an authorization id. */
    public Map<String, Object> run(String assessmentId, String authzId)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("authz_id", authzId);
        body.put("confirm", Boolean.TRUE);
        return http.postJson("/api/assessments/" + assessmentId + "/run", body);
    }

    public List<Object> assessments() throws HttpClient.ApiException {
        return Json.arr(http.getJson("/api/assessments"), "assessments");
    }

    public Map<String, Object> assessment(String id) throws HttpClient.ApiException {
        return http.getJson("/api/assessments/" + id);
    }

    public Map<String, Object> job(String id) throws HttpClient.ApiException {
        return http.getJson("/api/jobs/" + id);
    }

    public List<Object> findings(String assessmentId) throws HttpClient.ApiException {
        return Json.arr(http.getJson("/api/assessments/" + assessmentId + "/findings"), "findings");
    }

    public Map<String, Object> stats() throws HttpClient.ApiException {
        return http.getJson("/api/stats");
    }

    // ------------------------------------------------------------ reports ----

    public String reportUrl(String assessmentId, String format, String language) {
        return http.baseUrl() + "/api/assessments/" + assessmentId
                + "/report?fmt=" + format + "&lang=" + language;
    }

    /** Download a report. Uses the same bearer as every other call. */
    public byte[] downloadReport(String assessmentId, String format, String language)
            throws HttpClient.ApiException {
        return http.getBytes("/api/assessments/" + assessmentId
                + "/report?fmt=" + format + "&lang=" + language);
    }

    // -------------------------------------------------------------- audit ----

    public Map<String, Object> audit(int limit) throws HttpClient.ApiException {
        return http.getJson("/api/audit?limit=" + limit);
    }

    public Map<String, Object> auditVerify() throws HttpClient.ApiException {
        return http.getJson("/api/audit/verify");
    }

    // --------------------------------------------------- emergency stop ------

    public Map<String, Object> stopState() throws HttpClient.ApiException {
        return http.getJson("/api/emergency-stop");
    }

    public Map<String, Object> emergencyStop(String reason) throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("reason", reason == null ? "android operator emergency stop" : reason);
        return http.postJson("/api/emergency-stop", body);
    }

    public Map<String, Object> clearStop() throws HttpClient.ApiException {
        return http.postJson("/api/emergency-stop/clear", new LinkedHashMap<String, Object>());
    }

    // ---------------------------------------------------------------- artax --

    public Map<String, Object> artaxStatus() throws HttpClient.ApiException {
        return http.getJson("/api/artax/status");
    }

    public Map<String, Object> artaxAsk(String question, String assessmentId)
            throws HttpClient.ApiException {
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("question", question);
        if (assessmentId != null && !assessmentId.isEmpty()) body.put("assessment_id", assessmentId);
        body.put("history", new ArrayList<Object>());
        return http.postJson("/api/artax/ask", body);
    }

    // --------------------------------------------------------- integrations --

    public Map<String, Object> integrations() throws HttpClient.ApiException {
        return http.getJson("/api/integrations");
    }

    // ------------------------------------------------------------- helpers ---

    /** Probe a candidate server URL without disturbing an existing session. */
    public static Map<String, Object> probe(String baseUrl, int timeoutMs) throws IOException {
        HttpClient c = new HttpClient(baseUrl, HttpClient.defaultTransport());
        c.setTimeouts(timeoutMs, timeoutMs);
        try {
            return c.getJson("/api/health");
        } catch (HttpClient.ApiException e) {
            throw new IOException(e.getMessage(), e);
        }
    }
}
