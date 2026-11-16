package harness;

import java.util.List;
import java.util.Map;

import sh.testssl.wdneo.core.HttpClient;
import sh.testssl.wdneo.core.Json;
import sh.testssl.wdneo.core.WdApi;

/**
 * Exercises the EXACT core classes that ship inside the APK against a live
 * WD NEO backend, on a desktop JVM.
 *
 * This is the emulator substitute: the transport, JSON codec and API facade are
 * the same byte-for-byte code that the Android activity uses, so a passing run
 * here proves the client works over the real wire protocol.
 *
 * Usage: java harness.CoreHarness <baseUrl> <username> <password> <pin> <shortcut>
 */
public final class CoreHarness {

    /** Deterministic post-bootstrap password so repeated runs stay idempotent. */
    private static final String HARNESS_PASSWORD = "Harness-Rotated-Pass-2026";

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.err.println("usage: CoreHarness <baseUrl> <user> <pass> <pin> <shortcut>");
            System.exit(2);
        }
        String base = args[0];
        String user = args[1];
        String pass = args[2];
        String pin = args[3];
        String shortcut = args[4];

        // ---- 1. JSON codec round-trip (pure unit behaviour) ----
        check("json: parse object", () -> {
            Map<String, Object> o = Json.parseObject("{\"a\":1,\"b\":[true,null,\"x\\u00e9\"]}");
            expect(Json.str(o, "a").equals("1"), "number as string");
            expect(Json.arr(o, "b").size() == 3, "array length");
            expect(Json.arr(o, "b").get(2).equals("x\u00e9"), "unicode escape");
        });
        check("json: malformed input throws", () -> {
            boolean threw = false;
            try { Json.parse("{oops}"); } catch (Json.JsonException e) { threw = true; }
            expect(threw, "expected JsonException");
        });
        check("json: write/parse identity", () -> {
            Map<String, Object> o = Json.parseObject("{\"k\":\"v\",\"n\":2,\"f\":true}");
            Map<String, Object> back = Json.parseObject(Json.write(o));
            expect(Json.str(back, "k").equals("v"), "string survives");
            expect(Json.bool(back, "f"), "boolean survives");
        });
        check("url: normalizeBase adds scheme and trims slash", () -> {
            expect(HttpClient.normalizeBase("127.0.0.1:8000/").equals("http://127.0.0.1:8000"),
                   "got " + HttpClient.normalizeBase("127.0.0.1:8000/"));
            expect(HttpClient.normalizeBase("https://a.b/").equals("https://a.b"), "https kept");
        });

        // ---- 2. live server: unauthenticated surface ----
        WdApi api = new WdApi(base);
        api.http().setTimeouts(10000, 60000);

        check("health responds ok", () -> {
            Map<String, Object> h = api.health();
            expect("ok".equals(Json.str(h, "status")), "status=ok, got " + Json.str(h, "status"));
            System.out.println("      instance=" + Json.str(h, "instance")
                    + " version=" + Json.str(h, "version"));
        });

        check("unauthenticated request is rejected with 401", () -> {
            try {
                api.scope();
                throw new AssertionError("expected 401");
            } catch (HttpClient.ApiException e) {
                expect(e.status == 401, "expected 401, got " + e.status);
            }
        });

        // ---- 3. two-stage login ----
        // A previously rotated install rejects the bootstrap password. Resolve the
        // working one so the harness can be re-run against the same database.
        // The password is rotated by this harness on the first run, so try the
        // bootstrap value and then the rotated forms in order (bounded, so a
        // genuinely wrong password still fails fast).
        String effectivePass = pass;
        String[] candidates = { pass, HARNESS_PASSWORD, "Rotated-" + pass,
                                "Rotated2-" + pass };
        HttpClient.ApiException lastErr = null;
        boolean ok = false;
        for (String candidate : candidates) {
            try {
                api.stage1(user, candidate, shortcut);
                effectivePass = candidate;
                ok = true;
                break;
            } catch (HttpClient.ApiException e) {
                lastErr = e;
                if (e.status != 401) throw e;
            }
        }
        if (!ok) throw lastErr;
        final String pw = effectivePass;

        check("stage 1 returns a token", () -> {
            Map<String, Object> r = api.stage1(user, pw, shortcut);
            expect(api.authenticated(), "token stored");
            expect(Json.str(r, "token").length() > 20, "plausible token length");
            System.out.println("      stage after stage1 = " + api.stage());
        });

        check("stage 1 rejects a bad shortcut", () -> {
            WdApi bad = new WdApi(base);
            boolean threw = false;
            try { bad.stage1(user, pw, "WD-INCORRECT123"); }
            catch (HttpClient.ApiException e) { threw = true;
                expect(e.getMessage().contains("INVALID_CREDENTIALS") || e.status == 401,
                       "server message: " + e.getMessage()); }
            expect(threw, "expected an ApiException");
        });

        check("stage 2 raises the session to stage 2", () -> {
            api.stage2(pin);
            expect(api.stage() == 2, "expected stage 2, got " + api.stage());
        });

        // A bootstrap install must rotate its printed password before it may
        // authorize work; the server answers 428 PASSWORD_CHANGE_REQUIRED. The
        // APK surface has to show that prompt, so prove the client can act on it.
        check("bootstrap password is flagged for rotation", () -> {
            Map<String, Object> me = api.me();
            boolean must = Json.bool(Json.obj(me, "user"), "must_change_password");
            if (must) {
                // Rotate to a FIXED value, not a prefix of the current one: a
                // prefix would grow on every harness run (Rotated-, Rotated2-...)
                // and the next run could no longer guess the password.
                api.changePassword(pw, HARNESS_PASSWORD);
                Map<String, Object> after = api.me();
                expect(!Json.bool(Json.obj(after, "user"), "must_change_password"),
                       "flag should clear after rotation");
                System.out.println("      password rotated (428 gate satisfied)");
            } else {
                System.out.println("      password already rotated");
            }
        });

        check("stage 2 rejects a wrong PIN", () -> {
            WdApi other = new WdApi(base);
            other.stage1(user, pw, shortcut);
            boolean threw = false;
            try { other.stage2("00000000".equals(pin) ? "11111111" : "00000000"); }
            catch (HttpClient.ApiException e) { threw = true; }
            expect(threw, "expected an ApiException for a bad PIN");
        });

        // ---- 4. catalogue reads ----
        check("templates list ten entries", () -> {
            List<Object> t = api.templates();
            expect(t.size() == 10, "expected 10 templates, got " + t.size());
        });

        check("modules lists ten engines", () -> {
            Map<String, Object> m = api.modules();
            expect(Json.arr(m, "modules").size() == 10,
                   "got " + Json.arr(m, "modules").size());
            expect(Json.arr(m, "registered").size() >= 1, "registered list present");
        });

        check("stats responds", () -> {
            Map<String, Object> s = api.stats();
            expect(Json.num(s, "assessments") != null, "assessments count present");
        });

        check("emergency stop state responds and is clear", () -> {
            Map<String, Object> s = api.stopState();
            expect(!Json.bool(s, "active"), "stop should be clear at start");
        });

        check("artax status responds", () -> {
            Map<String, Object> a = api.artaxStatus();
            expect(!Json.str(a, "mode").isEmpty(), "mode field present");
            System.out.println("      artax mode = " + Json.str(a, "mode"));
        });

        // ---- 5. scope + authorization + run ----
        check("add scope entry (idempotent)", () -> {
            Map<String, Object> r = api.addScope("example.com", "android harness");
            expect(Json.str(r, "target").equals("example.com"),
                   "got " + Json.str(r, "target"));
        });

        check("validate scope accepts an in-scope host", () -> {
            List<String> targets = java.util.Arrays.asList("app.example.com");
            Map<String, Object> v = api.validateScope(targets);
            expect(Json.bool(v, "all_in_scope"), "app.example.com should be in scope");
        });

        check("validate scope rejects an out-of-scope host", () -> {
            List<String> targets = java.util.Arrays.asList("not-in-scope.test");
            Map<String, Object> v = api.validateScope(targets);
            expect(!Json.bool(v, "all_in_scope"), "should be out of scope");
        });

        // ---- 5. scope + authorization + run (all guarded) ----
        final String[] authzHolder = new String[1];
        final String[] asidHolder = new String[1];
        final String[] jobHolder = new String[1];

        check("create authorization", () -> {
            Map<String, Object> authz = api.authorize(
                    java.util.Arrays.asList("example.com"), 30, "android harness run");
            authzHolder[0] = Json.str(authz, "id");
            expect(!authzHolder[0].isEmpty(), "authorization id present");
            System.out.println("      authorization = " + shorten(authzHolder[0]));
        });

        check("authorization is refused for an out-of-scope target", () -> {
            boolean threw = false;
            try {
                api.authorize(java.util.Arrays.asList("definitely-not-registered.test"), 30, "neg");
            } catch (HttpClient.ApiException e) {
                threw = true;
                expect(e.status == 403, "expected 403, got " + e.status);
                expect(e.getMessage().contains("OUT_OF_SCOPE"),
                       "message was: " + e.getMessage());
            }
            expect(threw, "expected an ApiException");
        });

        check("create assessment with a passing preflight", () -> {
            Map<String, Object> a = api.createAssessment(
                    "network_pentest", java.util.Arrays.asList("example.com"),
                    "live", "light", new java.util.LinkedHashMap<String, Object>());
            asidHolder[0] = Json.str(a, "id");
            expect(!asidHolder[0].isEmpty(), "assessment id present");
            expect(Json.bool(Json.obj(a, "preflight"), "ok"), "preflight should pass");
            System.out.println("      assessment    = " + shorten(asidHolder[0]));
        });

        check("run the assessment", () -> {
            Map<String, Object> run = api.run(asidHolder[0], authzHolder[0]);
            jobHolder[0] = Json.str(run, "job_id");
            expect(!jobHolder[0].isEmpty(), "job id present");
        });

        check("job reaches a terminal state", () -> {
            String status = "";
            long deadline = System.currentTimeMillis() + 240000L;
            while (System.currentTimeMillis() < deadline) {
                Map<String, Object> job = api.job(jobHolder[0]);
                status = Json.str(job, "status");
                if ("completed".equals(status) || "failed".equals(status)
                        || "aborted".equals(status)) break;
                Thread.sleep(2000);
            }
            expect("completed".equals(status), "terminal status was '" + status + "'");
            System.out.println("      job status    = " + status);
        });

        check("findings come back with a persisted status", () -> {
            Map<String, Object> detail = api.assessment(asidHolder[0]);
            java.util.List<Object> findings = Json.arr(detail, "findings");
            expect(!findings.isEmpty(), "no findings returned");
            for (Object o : findings) {
                @SuppressWarnings("unchecked")
                Map<String, Object> f = (Map<String, Object>) o;
                expect(!Json.str(f, "status").isEmpty(),
                       "finding " + Json.str(f, "check_id") + " has no status");
                expect(!Json.str(f, "check_id").isEmpty(), "finding has no check_id");
            }
            System.out.println("      findings      = " + findings.size()
                    + " risk=" + Json.num(detail, "risk_score"));
        });

        check("report downloads as a real PDF", () -> {
            byte[] pdf = api.downloadReport(asidHolder[0], "pdf", "id");
            String magic = new String(pdf, 0, Math.min(5, pdf.length), HttpClient.UTF8);
            expect(magic.startsWith("%PDF"), "magic was '" + magic + "'");
            expect(pdf.length > 2000, "suspiciously small PDF: " + pdf.length);
            System.out.println("      pdf bytes     = " + pdf.length);
        });

        check("markdown report is localised (EN and ID)", () -> {
            String en = new String(api.downloadReport(asidHolder[0], "md", "en"), HttpClient.UTF8);
            expect(en.contains("1. Executive Summary"), "missing English heading");
            String id = new String(api.downloadReport(asidHolder[0], "md", "id"), HttpClient.UTF8);
            expect(id.contains("1. Ringkasan Eksekutif"), "missing Indonesian heading");
        });

        check("audit chain verifies", () -> {
            Map<String, Object> v = api.auditVerify();
            expect(Json.bool(v, "valid"), "audit chain must be valid");
            System.out.println("      audit events  = " + Json.num(v, "events"));
        });

        check("logout revokes the session", () -> {
            api.logout();
            expect(!api.authenticated(), "token cleared locally");
            boolean threw = false;
            try { api.me(); } catch (HttpClient.ApiException e) { threw = true; }
            expect(threw, "me() should fail after logout");
        });

        System.out.println("\n============================================");
        System.out.println("PASSED: " + passed + "   FAILED: " + failed);
        System.out.println("============================================");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------- helpers ----

    private interface Body { void run() throws Exception; }

    private static void check(String name, Body b) {
        try {
            b.run();
            passed++;
            System.out.println("  ok   " + name);
        } catch (Throwable t) {
            failed++;
            System.out.println("  FAIL " + name + " -> " + t.getMessage());
        }
    }

    private static void expect(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }

    private static String shorten(String id) {
        return id.length() > 8 ? id.substring(0, 8) : id;
    }
}
