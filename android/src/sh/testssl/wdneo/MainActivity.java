package sh.testssl.wdneo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import sh.testssl.wdneo.core.HttpClient;
import sh.testssl.wdneo.core.Json;
import sh.testssl.wdneo.core.WdApi;

/**
 * WD NEO operator console for Android.
 *
 * Two-stage login (WD shortcut + password, then a separate PIN), then a shell with
 * dashboard, scope, assessment, findings, reports and Artax.
 *
 * Every network call runs on a single background executor and UI updates are
 * marshalled back to the main thread; no networking happens on the UI thread, so
 * the app cannot ANR.
 *
 * Nothing is cached as "truth": each screen re-reads the server, because the
 * server is authoritative for scope, authorization and emergency-stop state.
 */
public class MainActivity extends Activity {

    private static final String PREFS = "wd_neo";
    private static final String K_SERVER = "server";
    private static final String K_USER = "user";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private WdApi api;
    private SharedPreferences prefs;

    // gate
    private View gate, shell;
    private View stage1Box, stage2Box;
    private EditText inServer, inUser, inPass, inShortcut, inPin, inScope, inTargets, inArtax;
    private TextView gateMsg1, gateMsg2, gateStatus;
    private Button btnConnect, btnStage1, btnBack, btnStage2;

    // shell
    private TextView badgeStage, badgeStop, dashState, dashBody, scopeBody,
            assessBody, findingsBody, reportsBody, artaxBody, artaxMode;
    private LinearLayout kpiRow, tabs;
    private Spinner spTemplate, spMode, spIntensity, spLang;
    private String[] navViews = {"dashboard", "scope", "assess", "findings", "reports", "artax"};
    private String[] navLabels = {"DASHBOARD", "SCOPE", "ASSESS", "FINDINGS", "REPORTS", "ARTAX"};
    private String currentView = "dashboard";

    // template + assessment state
    private final List<String> templateIds = new ArrayList<String>();
    private final List<String> templateLabels = new ArrayList<String>();
    private String currentAssessmentId = "";

    // ------------------------------------------------------------------ lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        bind();
        wire();

        String server = prefs.getString(K_SERVER, "http://10.0.2.2:8000");
        String user = prefs.getString(K_USER, "");
        inServer.setText(server);
        inUser.setText(user);
        api = new WdApi(server);
        api.http().setTimeouts(12000, 60000);
        gateStatus.setText("server: " + api.baseUrl());
    }

    @Override
    protected void onDestroy() {
        io.shutdownNow();
        super.onDestroy();
    }

    private void bind() {
        gate = findViewById(R.id.gate);
        shell = findViewById(R.id.shell);
        stage1Box = findViewById(R.id.stage1_box);
        stage2Box = findViewById(R.id.stage2_box);
        inServer = findViewById(R.id.in_server);
        inUser = findViewById(R.id.in_user);
        inPass = findViewById(R.id.in_pass);
        inShortcut = findViewById(R.id.in_shortcut);
        inPin = findViewById(R.id.in_pin);
        inScope = findViewById(R.id.in_scope);
        inTargets = findViewById(R.id.in_targets);
        inArtax = findViewById(R.id.in_artax);
        gateMsg1 = findViewById(R.id.gate_msg1);
        gateMsg2 = findViewById(R.id.gate_msg2);
        gateStatus = findViewById(R.id.gate_status);
        btnConnect = findViewById(R.id.btn_connect);
        btnStage1 = findViewById(R.id.btn_stage1);
        btnBack = findViewById(R.id.btn_back);
        btnStage2 = findViewById(R.id.btn_stage2);

        badgeStage = findViewById(R.id.badge_stage);
        badgeStop = findViewById(R.id.badge_stop);
        dashState = findViewById(R.id.dash_state);
        dashBody = findViewById(R.id.dash_body);
        scopeBody = findViewById(R.id.scope_body);
        assessBody = findViewById(R.id.assess_body);
        findingsBody = findViewById(R.id.findings_body);
        reportsBody = findViewById(R.id.reports_body);
        artaxBody = findViewById(R.id.artax_body);
        artaxMode = findViewById(R.id.artax_mode);
        kpiRow = findViewById(R.id.kpi_row);
        tabs = findViewById(R.id.tabs);
        spTemplate = findViewById(R.id.sp_template);
        spMode = findViewById(R.id.sp_mode);
        spIntensity = findViewById(R.id.sp_intensity);
        spLang = findViewById(R.id.sp_lang);
    }

    private void wire() {
        btnConnect.setOnClickListener(v -> doConnect());
        btnStage1.setOnClickListener(v -> doStage1());
        btnStage2.setOnClickListener(v -> doStage2());
        btnBack.setOnClickListener(v -> showStage(1));

        findViewById(R.id.btn_refresh).setOnClickListener(v -> refreshAll());
        findViewById(R.id.btn_logout).setOnClickListener(v -> doLogout());
        findViewById(R.id.btn_verify_audit).setOnClickListener(v -> doVerifyAudit());
        findViewById(R.id.btn_stop).setOnClickListener(v -> doEmergencyStop());
        findViewById(R.id.btn_clear_stop).setOnClickListener(v -> doClearStop());
        findViewById(R.id.btn_add_scope).setOnClickListener(v -> doAddScope());
        findViewById(R.id.btn_validate).setOnClickListener(v -> doValidate());
        findViewById(R.id.btn_run).setOnClickListener(v -> doAuthorizeAndRun());
        findViewById(R.id.btn_load_findings).setOnClickListener(v -> loadFindings());
        findViewById(R.id.btn_open_pdf).setOnClickListener(v -> openReport(false));
        findViewById(R.id.btn_share_pdf).setOnClickListener(v -> openReport(true));
        findViewById(R.id.btn_ask).setOnClickListener(v -> doAsk());

        spMode.setAdapter(simpleAdapter(new String[]{"live", "lab"}));
        spIntensity.setAdapter(simpleAdapter(new String[]{"light", "normal", "deep"}));
        spIntensity.setSelection(1);
        spLang.setAdapter(simpleAdapter(new String[]{"en", "id"}));

        buildTabs();
    }

    private ArrayAdapter<String> simpleAdapter(String[] values) {
        ArrayAdapter<String> a = new ArrayAdapter<String>(this,
                android.R.layout.simple_spinner_item, values);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return a;
    }

    private void buildTabs() {
        tabs.removeAllViews();
        for (int i = 0; i < navViews.length; i++) {
            final String view = navViews[i];
            TextView tab = new TextView(this);
            tab.setText(navLabels[i]);
            tab.setTextSize(10.5f);
            tab.setLetterSpacing(0.08f);
            tab.setTypeface(android.graphics.Typeface.MONOSPACE);
            tab.setGravity(android.view.Gravity.CENTER);
            tab.setPadding(dp(12), dp(9), dp(12), dp(9));
            tab.setBackgroundResource(R.drawable.bg_tab);
            tab.setTextColor(getResources().getColorStateList(R.color.tab_text));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.rightMargin = dp(6);
            tab.setLayoutParams(lp);
            tab.setOnClickListener(v -> showView(view));
            tab.setTag(view);
            tabs.addView(tab);
        }
        updateTabSelection();
    }

    private void updateTabSelection() {
        for (int i = 0; i < tabs.getChildCount(); i++) {
            View child = tabs.getChildAt(i);
            child.setSelected(navViews[i].equals(currentView));
        }
    }

    private void showView(String view) {
        currentView = view;
        int[] ids = {R.id.view_dashboard, R.id.view_scope, R.id.view_assess,
                R.id.view_findings, R.id.view_reports, R.id.view_artax};
        for (int i = 0; i < ids.length; i++) {
            findViewById(ids[i]).setVisibility(navViews[i].equals(view) ? View.VISIBLE : View.GONE);
        }
        updateTabSelection();
        if (!api.authenticated()) return;
        if ("scope".equals(view)) loadScope();
        else if ("findings".equals(view)) loadFindings();
        else if ("reports".equals(view)) loadAssessments();
        else if ("artax".equals(view)) loadArtaxStatus();
        else if ("dashboard".equals(view)) refreshAll();
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    // ---------------------------------------------------------------- threading

    /** Work returning a value, executed on the IO thread. */
    private interface Job<T> { T run() throws Exception; }

    /** Work executed on the IO thread for its side effects only. */
    private interface Task { void run() throws Exception; }

    /** Run on the IO thread; `done` runs on the UI thread (null on failure). */
    private <T> void async(Job<T> work, UiAction done) {
        io.execute(() -> {
            T value;
            try {
                value = work.run();
            } catch (final Exception e) {
                if (done != null) ui.post(() -> deliver(done, e));
                return;
            }
            if (done != null) ui.post(() -> deliver(done, null));
        });
    }

    /** Hand control back to the UI thread, converting a render failure to a toast. */
    private void deliver(UiAction done, Exception error) {
        try {
            done.run(error);
        } catch (Exception renderFailure) {
            toast("ui: " + err(renderFailure));
        }
    }

    /** Overload for side-effect-only work, so lambdas need no dummy return. */
    private void run(Task work, UiAction done) {
        async(() -> { work.run(); return null; }, done);
    }

    private interface UiAction { void run(Exception error) throws Exception; }

    /** Invoke an API call from a lambda body, surfacing checked exceptions. */
    private static <T> T call(ApiCall<T> c) throws Exception {
        return c.get();
    }

    private interface ApiCall<T> { T get() throws Exception; }


    private void toast(final String msg) {
        ui.post(() -> Toast.makeText(MainActivity.this, msg, Toast.LENGTH_SHORT).show());
    }

    private void hideKeyboard() {
        View focus = getCurrentFocus();
        if (focus == null) return;
        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) imm.hideSoftInputFromWindow(focus.getWindowToken(), 0);
    }

    private static String err(Throwable t) {
        String m = t.getMessage();
        return (m == null || m.trim().isEmpty()) ? t.getClass().getSimpleName() : m;
    }

    // ================================================================ GATE ====

    private void doConnect() {
        final String server = HttpClient.normalizeBase(inServer.getText().toString());
        if (server.isEmpty()) { gateMsg1.setText("enter a server URL"); return; }
        btnConnect.setEnabled(false);
        gateMsg1.setText(getString(R.string.msg_checking));
        api = new WdApi(server);
        api.http().setTimeouts(12000, 60000);
        async(() -> {
            Map<String, Object> h = api.health();
            final String instance = Json.str(h, "instance");
            final String version = Json.str(h, "version");
            return instance + "|" + version;
        }, e -> {
            btnConnect.setEnabled(true);
            if (e != null) {
                gateMsg1.setText(getString(R.string.msg_offline) + " (" + err(e) + ")");
                return;
            }
            gateMsg1.setText("connected");
            prefs.edit().putString(K_SERVER, server).apply();
            gateStatus.setText(api.baseUrl());
        });
    }

    private void doStage1() {
        final String server = HttpClient.normalizeBase(inServer.getText().toString());
        final String user = inUser.getText().toString().trim();
        final String pass = inPass.getText().toString();
        final String shortcut = inShortcut.getText().toString().trim();
        if (user.isEmpty() || pass.isEmpty() || shortcut.isEmpty()) {
            gateMsg1.setText("operator, password and WD shortcut are all required");
            return;
        }
        hideKeyboard();
        gateMsg1.setText("verifying…");
        btnStage1.setEnabled(false);
        api = new WdApi(server);
        api.http().setTimeouts(12000, 60000);
        run(() -> api.stage1(user, pass, shortcut), e -> {
            btnStage1.setEnabled(false);
            if (e != null) {
                gateMsg1.setText(err(e));
                btnStage1.setEnabled(true);
                return;
            }
            prefs.edit().putString(K_SERVER, server)
                        .putString(K_USER, user).apply();
            gateMsg1.setText("");
            inPin.setText("");
            gateMsg2.setText(getString(R.string.msg_stage1_ok));
            showStage(2);
        });
    }

    private void doStage2() {
        final String pin = inPin.getText().toString().trim();
        if (pin.isEmpty()) { gateMsg2.setText("enter the PIN"); return; }
        hideKeyboard();
        gateMsg2.setText("authorizing…");
        btnStage2.setEnabled(false);
        run(() -> api.stage2(pin), e -> {
            btnStage2.setEnabled(true);
            if (e != null) { gateMsg2.setText(err(e)); return; }
            // a bootstrap install must rotate its printed password first
            checkRotationThenEnter();
        });
    }

    private void checkRotationThenEnter() {
        io.execute(() -> {
            try {
                Map<String, Object> me = api.me();
                final boolean must = Json.bool(Json.obj(me, "user"), "must_change_password");
                final int stage = (int) Json.num(me, "stage").doubleValue();
                ui.post(() -> {
                    badgeStage.setText("STAGE " + stage);
                    if (must) promptPasswordRotation();
                    enterShell();
                });
            } catch (final Exception ex) {
                ui.post(() -> gateMsg2.setText(err(ex)));
            }
        });
    }

    /** A 428-gated operator cannot authorize work until the printed password is replaced. */
    private void promptPasswordRotation() {
        new android.app.AlertDialog.Builder(this)
            .setTitle("Rotate bootstrap password")
            .setMessage("This operator still uses the one-time password printed on first boot.\n"
                    + "Authorizing or executing tests is blocked until it is changed.")
            .setPositiveButton("ROTATE NOW", (d, w) -> showRotationDialog())
            .setNegativeButton("LATER", null)
            .show();
    }

    private void showRotationDialog() {
        final EditText input = new EditText(this);
        input.setHint("new password (12+ chars, 3 character classes)");
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        int pad = dp(16);
        LinearLayout box = new LinearLayout(this);
        box.setPadding(pad, pad, pad, 0);
        box.addView(input, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        new android.app.AlertDialog.Builder(this)
            .setTitle("New operator password")
            .setView(box)
            .setPositiveButton("SAVE", (d, w) -> {
                final String oldPass = inPass.getText().toString();
                final String newPass = input.getText().toString().trim();
                if (newPass.length() < 12) { toast("password must be 12+ characters"); return; }
                run(() -> api.changePassword(oldPass, newPass), e2 -> {
                    if (e2 != null) { toast(err(e2)); return; }
                    inPass.setText(newPass);
                    toast("password rotated");
                    refreshAll();
                });
            })
            .setNegativeButton("CANCEL", null)
            .show();
    }

    private void showStage(int stage) {
        stage1Box.setVisibility(stage == 1 ? View.VISIBLE : View.GONE);
        stage2Box.setVisibility(stage == 2 ? View.VISIBLE : View.GONE);
        if (stage == 1) btnStage1.setEnabled(true);
    }

    private void enterShell() {
        gate.setVisibility(View.GONE);
        shell.setVisibility(View.VISIBLE);
        gateMsg1.setText("");
        gateMsg2.setText("");
        assembleTemplates();
        refreshAll();
    }

    // =============================================================== SHELL ====

    private void refreshAll() {
        if (!api.authenticated()) return;
        run(() -> api.stats(), e -> {
            if (e != null) { dashState.setText("stats: " + err(e)); return; }
            Map<String, Object> s = api.stats();
            renderKpis(s);
            renderPlatformState(s);
        });
        run(() -> api.stopState(), e -> {
            if (e != null) return;
            boolean active = Json.bool(api.stopState(), "active");
            badgeStop.setVisibility(active ? View.VISIBLE : View.GONE);
            dashState.setText(active ? getString(R.string.msg_stop_active) : "");
            dashState.setTextColor(active ? 0xFFFCA5A5 : 0xFF7E8FA3);
        });
    }

    private void renderKpis(Map<String, Object> s) {
        kpiRow.removeAllViews();
        Map<String, Object> sev = Json.obj(s, "findings_by_severity");
        addKpi(String.valueOf(fmt(Json.num(s, "assessments"))), "ASSESSMENTS");
        addKpi(String.valueOf(fmt(Json.num(s, "findings"))), "FINDINGS");
        addKpi(String.valueOf(fmt(Json.num(sev, "critical"))), "CRITICAL");
        addKpi(String.valueOf(fmt(Json.num(sev, "high"))), "HIGH");
        addKpi(String.valueOf(fmt(Json.num(sev, "medium"))), "MEDIUM");
    }

    private void addKpi(String value, String label) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.bg_card);
        box.setPadding(dp(12), dp(10), dp(12), dp(10));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        lp.rightMargin = dp(6);
        box.setLayoutParams(lp);

        TextView v = new TextView(this);
        v.setText(value);
        v.setTextSize(20f);
        v.setTextColor(0xFFEAF3FB);
        v.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);

        TextView l = new TextView(this);
        l.setText(label);
        l.setTextSize(8.5f);
        l.setTextColor(0xFF7E8FA3);
        l.setLetterSpacing(0.08f);

        box.addView(v);
        box.addView(l);
        kpiRow.addView(box);
    }

    private static String fmt(Double d) {
        if (d == null) return "—";
        return String.valueOf(d.longValue());
    }

    private void renderPlatformState(Map<String, Object> s) {
        StringBuilder sb = new StringBuilder();
        Map<String, Object> stop = Json.obj(s, "emergency_stop");
        sb.append("emergency stop : ").append(Json.bool(stop, "active") ? "ACTIVE" : "clear").append('\n');
        sb.append("audit events   : ").append(fmt(Json.num(s, "audit_events"))).append('\n');
        Double risk = Json.num(s, "avg_risk");
        sb.append("average risk   : ").append(risk == null ? "—" : String.valueOf(risk)).append('\n');
        sb.append("server         : ").append(api.baseUrl()).append('\n');
        dashBody.setText(sb.toString());
    }

    private void doLogout() {
        run(() -> api.logout(), e -> {
            shell.setVisibility(View.GONE);
            gate.setVisibility(View.VISIBLE);
            showStage(1);
            gateMsg1.setText("logged out — session revoked server-side");
            inPin.setText("");
        });
    }

    private void doVerifyAudit() {
        run(() -> api.auditVerify(), e -> {
            if (e != null) { dashBody.setText("audit: " + err(e)); return; }
            Map<String, Object> v = api.auditVerify();
            boolean ok = Json.bool(v, "valid");
            StringBuilder sb = new StringBuilder();
            sb.append("audit chain : ").append(ok ? "VALID" : "BROKEN").append('\n');
            sb.append("events      : ").append(fmt(Json.num(v, "events"))).append('\n');
            String head = Json.str(v, "head");
            if (!head.isEmpty()) sb.append("head        : ").append(head).append('\n');
            if (!ok) sb.append("broken at   : ").append(Json.str(v, "broken_at")).append('\n');
            dashBody.setText(sb.toString());
        });
    }

    private void doEmergencyStop() {
        new android.app.AlertDialog.Builder(this)
            .setTitle("Emergency stop")
            .setMessage("Abort running jobs and revoke all authorizations and sessions?")
            .setPositiveButton("STOP", (d, w) -> run(() -> api.emergencyStop("android operator"), e -> {
                if (e != null) { toast(err(e)); return; }
                toast("emergency stop active");
                refreshAll();
            }))
            .setNegativeButton("CANCEL", null)
            .show();
    }

    private void doClearStop() {
        run(() -> api.clearStop(), e -> {
            if (e != null) { toast(err(e)); return; }
            toast("stop cleared");
            refreshAll();
        });
    }

    // ---------------------------------------------------------------- scope ----

    private void loadScope() {
        run(() -> api.scope(), e -> {
            if (e != null) { scopeBody.setText("scope: " + err(e)); return; }
            List<Object> rows = api.scope();
            if (rows.isEmpty()) { scopeBody.setText(getString(R.string.msg_no_scope)); return; }
            StringBuilder sb = new StringBuilder();
            for (Object o : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) o;
                sb.append(String.format("%-28s %-12s %s%n",
                        Json.str(m, "target"), Json.str(m, "target_type"),
                        Json.bool(m, "active") ? "active" : "inactive"));
            }
            scopeBody.setText(sb.toString());
        });
    }

    private void doAddScope() {
        final String target = inScope.getText().toString().trim();
        if (target.isEmpty()) { toast("enter a target"); return; }
        hideKeyboard();
        run(() -> api.addScope(target, "android operator"), e -> {
            if (e != null) { toast(err(e)); return; }
            inScope.setText("");
            toast("scope added: " + target);
            loadScope();
        });
    }

    // ----------------------------------------------------------- assessment ----

    private void assembleTemplates() {
        run(() -> api.templates(), e -> {
            if (e != null) { assessBody.setText("templates: " + err(e)); return; }
            List<Object> rows = api.templates();
            templateIds.clear();
            templateLabels.clear();
            for (Object o : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) o;
                templateIds.add(Json.str(m, "id"));
                String title = Json.str(m, "title");
                if (title.isEmpty()) title = Json.str(m, "id");
                templateLabels.add(title);
            }
            spTemplate.setAdapter(simpleAdapter(
                    templateLabels.toArray(new String[0])));
            if (!templateIds.isEmpty()) suggestTargetFor(templateIds.get(0));
            // A NAMED inner class (not an anonymous one): d8/R8 8.2.2 crashes with
            // an internal NullPointerException while dexing anonymous classes that
            // implement a generic interface method here, so this stays explicit.
            spTemplate.setOnItemSelectedListener(new TemplateSelectListener(this));
        });
    }

    /** Prefill the target field with the shape the chosen template expects. */
    private void suggestTargetFor(String templateId) {
        String hint;
        if ("can_pentest".equals(templateId)) hint = "can:can0";
        else if ("scada_pentest".equals(templateId)) hint = "modbus://127.0.0.1:502";
        else if ("webapp_pentest".equals(templateId)) hint = "http://127.0.0.1:8000";
        else hint = "example.com";
        inTargets.setHint(hint);
    }

    private String selectedTemplate() {
        int pos = spTemplate.getSelectedItemPosition();
        return (pos >= 0 && pos < templateIds.size()) ? templateIds.get(pos) : "network_pentest";
    }

    /**
     * Feeds the target-field suggestion when the operator picks a template.
     *
     * Declared <b>static</b> on purpose: the bundled d8 (R8 8.2.2) throws an
     * internal NullPointerException while dexing a NON-static inner class that
     * implements a generic Android interface (reproduced with a 6-line class).
     * A static nested class dexes cleanly, so the activity is passed explicitly.
     */
    static final class TemplateSelectListener
            implements android.widget.AdapterView.OnItemSelectedListener {
        private final MainActivity host;

        TemplateSelectListener(MainActivity host) {
            this.host = host;
        }

        @Override
        public void onItemSelected(android.widget.AdapterView<?> parent, View view,
                                   int position, long id) {
            if (position >= 0 && position < host.templateIds.size()) {
                host.suggestTargetFor(host.templateIds.get(position));
            }
        }

        @Override
        public void onNothingSelected(android.widget.AdapterView<?> parent) {
            // nothing to prefill
        }
    }

    private List<String> targetList() {
        List<String> out = new ArrayList<String>();
        String raw = inTargets.getText().toString();
        for (String part : raw.split("[,\\n]")) {
            String t = part.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }

    private void doValidate() {
        final List<String> targets = targetList();
        if (targets.isEmpty()) { toast("enter at least one target"); return; }
        run(() -> api.validateScope(targets), e -> {
            if (e != null) { assessBody.setText("validate: " + err(e)); return; }
            Map<String, Object> v = api.validateScope(targets);
            boolean all = Json.bool(v, "all_in_scope");
            StringBuilder sb = new StringBuilder();
            sb.append("template : ").append(selectedTemplate()).append('\n');
            sb.append("mode     : ").append(spMode.getSelectedItem()).append('\n');
            sb.append("scope    : ").append(all ? "ALL IN SCOPE" : "OUT OF SCOPE").append('\n');
            for (Object o : Json.arr(v, "targets")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) o;
                sb.append("  ").append(Json.str(m, "target")).append("  ")
                  .append(Json.bool(m, "in_scope") ? "in-scope" : "OUT-OF-SCOPE")
                  .append('\n');
            }
            assessBody.setText(sb.toString());
        });
    }

    private void doAuthorizeAndRun() {
        final List<String> targets = targetList();
        if (targets.isEmpty()) { toast("enter at least one target"); return; }
        final String template = selectedTemplate();
        final String mode = String.valueOf(spMode.getSelectedItem());
        final String intensity = String.valueOf(spIntensity.getSelectedItem());
        final String lang = String.valueOf(spLang.getSelectedItem());

        new android.app.AlertDialog.Builder(this)
            .setTitle("Authorize and execute")
            .setMessage("Template: " + template + "\nMode: " + mode + "\nIntensity: " + intensity
                    + "\nTargets: " + join(targets) + "\n\nThis records an authorization in the audit chain.")
            .setPositiveButton("EXECUTE", (d, w) -> {
                hideKeyboard();
                assessBody.setText(getString(R.string.msg_executing));
                async(() -> {
                    Map<String, Object> authz = api.authorize(targets, 30,
                            "android operator: " + template);
                    String authzId = Json.str(authz, "id");
                    Map<String, Object> created = api.createAssessment(
                            template, targets, mode, intensity, new LinkedHashMap<String, Object>());
                    String asid = Json.str(created, "id");
                    currentAssessmentId = asid;
                    Map<String, Object> run = api.run(asid, authzId);
                    return Json.str(run, "job_id");
                }, e -> {
                    if (e != null) { assessBody.setText("run failed: " + err(e)); return; }
                    assessBody.setText("authorized · assessment " + shortId(currentAssessmentId)
                            + "\nwaiting for the job…");
                    pollJob(currentAssessmentId);
                });
            })
            .setNegativeButton("CANCEL", null)
            .show();
    }

    private void pollJob(final String assessmentId) {
        io.execute(() -> {
            String status = "";
            long deadline = System.currentTimeMillis() + 300000L;
            try {
                while (System.currentTimeMillis() < deadline) {
                    List<Object> rows = api.assessments();
                    for (Object o : rows) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> m = (Map<String, Object>) o;
                        if (assessmentId.equals(Json.str(m, "id"))) {
                            status = Json.str(m, "status");
                        }
                    }
                    if ("completed".equals(status) || "failed".equals(status)
                            || "aborted".equals(status)) break;
                    final String s = status.isEmpty() ? "running" : status;
                    ui.post(() -> assessBody.setText("assessment " + shortId(assessmentId)
                            + "\nstatus: " + s));
                    Thread.sleep(2500);
                }
                final String finalStatus = status;
                Map<String, Object> detail = api.assessment(assessmentId);
                final Double risk = Json.num(detail, "risk_score");
                final int findings = Json.arr(detail, "findings").size();
                ui.post(() -> {
                    assessBody.setText("assessment " + shortId(assessmentId)
                            + "\nstatus: " + finalStatus
                            + "\nfindings: " + findings
                            + "\nrisk: " + (risk == null ? "—" : String.valueOf(risk)));
                    loadFindings();
                });
            } catch (final Exception ex) {
                ui.post(() -> assessBody.setText("poll failed: " + err(ex)));
            }
        });
    }

    private void loadAssessments() {
        run(() -> api.assessments(), e -> {
            if (e != null) { reportsBody.setText("assessments: " + err(e)); return; }
            List<Object> rows = api.assessments();
            if (rows.isEmpty()) { reportsBody.setText("no assessments yet — run one from ASSESS"); return; }
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%-10s %-20s %-10s %s%n", "ID", "TEMPLATE", "STATUS", "RISK"));
            for (Object o : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) o;
                sb.append(String.format("%-10s %-20s %-10s %s%n",
                        shortId(Json.str(m, "id")), Json.str(m, "template"),
                        Json.str(m, "status"),
                        Json.num(m, "risk_score") == null ? "—" : Json.num(m, "risk_score")));
            }
            if (currentAssessmentId.isEmpty() && !rows.isEmpty()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> first = (Map<String, Object>) rows.get(0);
                currentAssessmentId = Json.str(first, "id");
            }
            sb.append("\nselected: ").append(shortId(currentAssessmentId));
            reportsBody.setText(sb.toString());
        });
    }

    // ------------------------------------------------------------- findings ----

    private void loadFindings() {
        if (currentAssessmentId.isEmpty()) { findingsBody.setText("run an assessment first"); return; }
        run(() -> api.assessment(currentAssessmentId), e -> {
            if (e != null) { findingsBody.setText("findings: " + err(e)); return; }
            Map<String, Object> d = api.assessment(currentAssessmentId);
            List<Object> rows = Json.arr(d, "findings");
            StringBuilder sb = new StringBuilder();
            Map<String, Object> summary = Json.obj(d, "summary");
            sb.append("assessment ").append(shortId(currentAssessmentId)).append('\n');
            sb.append("by status : ").append(Json.obj(summary, "by_status")).append('\n');
            sb.append("by source : ").append(Json.obj(summary, "by_source")).append("\n\n");
            for (Object o : rows) {
                @SuppressWarnings("unchecked")
                Map<String, Object> f = (Map<String, Object>) o;
                sb.append(String.format("%-9s %-11s %-7s %s%n",
                        Json.str(f, "check_id"), Json.str(f, "status"),
                        Json.str(f, "severity"), Json.str(f, "title")));
            }
            findingsBody.setText(sb.toString());
        });
    }

    // -------------------------------------------------------------- reports ----

    private void openReport(boolean share) {
        if (currentAssessmentId.isEmpty()) { toast("run an assessment first"); return; }
        final String lang = String.valueOf(spLang.getSelectedItem());
        toast("fetching PDF…");
        run(() -> api.downloadReport(currentAssessmentId, "pdf", lang), e -> {
            if (e != null) { reportsBody.setText("report: " + err(e)); return; }
            try {
                byte[] pdf = api.downloadReport(currentAssessmentId, "pdf", lang);
                java.io.File dir = new java.io.File(getCacheDir(), "reports");
                if (!dir.exists() && !dir.mkdirs()) throw new java.io.IOException("cannot create cache dir");
                java.io.File out = new java.io.File(dir, "wd-neo-"
                        + shortId(currentAssessmentId) + "-" + lang + ".pdf");
                java.io.FileOutputStream fos = new java.io.FileOutputStream(out);
                try { fos.write(pdf); } finally { fos.close(); }

                android.net.Uri uri = androidxFreeUri(out);
                reportsBody.setText("report saved\n" + out.getAbsolutePath()
                        + "\n" + pdf.length + " bytes");
                Intent intent = new Intent(share ? Intent.ACTION_SEND : Intent.ACTION_VIEW);
                intent.setType("application/pdf");
                if (share) {
                    intent.putExtra(Intent.EXTRA_STREAM, uri);
                } else {
                    intent.setDataAndType(uri, "application/pdf");
                }
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivity(Intent.createChooser(intent, "WD NEO report"));
            } catch (Exception ex) {
                reportsBody.setText("report failed: " + err(ex));
            }
        });
    }

    /**
     * A content:// URI the other app can actually read.
     *
     * Uses FileProvider when the library is present; without AppCompat the
     * manifest still declares it, so this resolves at runtime.
     */
    private Uri androidxFreeUri(java.io.File file) {
        try {
            Class<?> fp = Class.forName("androidx.core.content.FileProvider");
            java.lang.reflect.Method m = fp.getMethod("getUriForFile",
                    Context.class, String.class, java.io.File.class);
            return (Uri) m.invoke(null, this, getPackageName() + ".files", file);
        } catch (Exception ignored) {
            return Uri.fromFile(file);
        }
    }

    // ---------------------------------------------------------------- artax ----

    private void loadArtaxStatus() {
        run(() -> api.artaxStatus(), e -> {
            if (e != null) { artaxMode.setText("artax: " + err(e)); return; }
            Map<String, Object> s = api.artaxStatus();
            artaxMode.setText("MODE " + Json.str(s, "mode").toUpperCase()
                    + "   parser " + Json.str(s, "parser")
                    + "\n" + Json.str(s, "note"));
        });
    }

    private void doAsk() {
        final String q = inArtax.getText().toString().trim();
        if (q.isEmpty()) { toast("ask a question"); return; }
        hideKeyboard();
        artaxBody.setText("thinking…");
        run(() -> api.artaxAsk(q, currentAssessmentId), e -> {
            if (e != null) { artaxBody.setText("artax: " + err(e)); return; }
            Map<String, Object> r = api.artaxAsk(q, currentAssessmentId);
            String answer = Json.str(r, "answer");
            if (answer.isEmpty()) answer = Json.write(r);
            artaxBody.setText(answer);
            inArtax.setText("");
        });
    }

    // --------------------------------------------------------------- helpers ---

    private static String shortId(String id) {
        if (id == null) return "";
        return id.length() > 8 ? id.substring(0, 8) : id;
    }

    private static String join(List<String> parts) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(parts.get(i));
        }
        return sb.toString();
    }
}
