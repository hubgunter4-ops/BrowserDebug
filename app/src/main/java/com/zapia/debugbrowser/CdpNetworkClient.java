package com.zapia.debugbrowser;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal embedded CDP transport for debug WebView builds.
 * It uses WebView's abstract Unix socket and a small RFC 6455 text-frame transport,
 * avoiding a public TCP port and external dependencies.
 */
public final class CdpNetworkClient {
    public interface Listener {
        void onStatus(String status);
        void onNetworkRecord(String record);
    }

    private final int pid;
    private final Listener listener;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final AtomicInteger commandId = new AtomicInteger(1);
    private volatile boolean running;
    private volatile LocalSocket socket;
    private OutputStream output;

    public CdpNetworkClient(int pid, Listener listener) {
        this.pid = pid;
        this.listener = listener;
    }

    public void start() {
        if (running) return;
        running = true;
        executor.execute(this::connectAndRead);
    }

    public void stop() {
        running = false;
        try { if (socket != null) socket.close(); } catch (Exception ignored) { }
        executor.shutdownNow();
    }

    private void connectAndRead() {
        String endpoint = "webview_devtools_remote_" + pid;
        try {
            LocalSocket probe = open(endpoint);
            String jsonList = httpRequest(probe, "/json/list");
            probe.close();
            JSONObject target = firstTarget(jsonList);
            if (target == null) throw new IllegalStateException("No hay target CDP para este WebView");

            String webSocketUrl = target.optString("webSocketDebuggerUrl", "");
            int pathStart = webSocketUrl.indexOf('/', webSocketUrl.indexOf("//") + 2);
            String path = pathStart >= 0 ? webSocketUrl.substring(pathStart) : "/devtools/page/1";

            socket = open(endpoint);
            websocketHandshake(socket, path);
            output = socket.getOutputStream();
            sendCommand("Network.enable", new JSONObject());
            sendCommand("Page.enable", new JSONObject());
            sendCommand("Runtime.enable", new JSONObject());
            listener.onStatus("CDP conectado");

            while (running) {
                String message = readTextFrame(socket.getInputStream());
                if (message == null) break;
                handleMessage(message);
            }
        } catch (Exception error) {
            listener.onStatus("CDP no disponible: " + safeMessage(error));
        } finally {
            running = false;
            try { if (socket != null) socket.close(); } catch (Exception ignored) { }
        }
    }

    private LocalSocket open(String endpoint) throws Exception {
        LocalSocket local = new LocalSocket();
        local.connect(new LocalSocketAddress(endpoint, LocalSocketAddress.Namespace.ABSTRACT));
        return local;
    }

    private String httpRequest(LocalSocket local, String path) throws Exception {
        OutputStream out = local.getOutputStream();
        InputStream in = local.getInputStream();
        out.write(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return readHttpBody(in);
    }

    private JSONObject firstTarget(String body) throws Exception {
        int start = body.indexOf('[');
        if (start < 0) return null;
        org.json.JSONArray targets = new org.json.JSONArray(body.substring(start));
        for (int i = 0; i < targets.length(); i++) {
            JSONObject target = targets.optJSONObject(i);
            if (target != null && "page".equals(target.optString("type"))) return target;
        }
        return targets.length() == 0 ? null : targets.optJSONObject(0);
    }

    private void websocketHandshake(LocalSocket local, String path) throws Exception {
        String key = randomKey();
        OutputStream out = local.getOutputStream();
        InputStream in = local.getInputStream();
        String request = "GET " + path + " HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();
        String headers = readUntilHeaderEnd(in);
        if (!headers.startsWith("HTTP/1.1 101")) {
            throw new IllegalStateException("Handshake CDP rechazado: " + headers.split("\r\n", 2)[0]);
        }
    }

    private void sendCommand(String method, JSONObject params) throws Exception {
        JSONObject command = new JSONObject();
        command.put("id", commandId.getAndIncrement());
        command.put("method", method);
        command.put("params", params);
        sendTextFrame(command.toString());
    }

    private void handleMessage(String message) {
        try {
            JSONObject event = new JSONObject(message);
            String method = event.optString("method");
            JSONObject params = event.optJSONObject("params");
            if ("Network.requestWillBeSent".equals(method) && params != null) {
                JSONObject request = params.optJSONObject("request");
                if (request != null) listener.onNetworkRecord("REQUEST " + params.optString("requestId") + "  " + request.optString("method") + "  " + request.optString("url"));
            } else if ("Network.responseReceived".equals(method) && params != null) {
                JSONObject response = params.optJSONObject("response");
                if (response != null) listener.onNetworkRecord("RESPONSE " + params.optString("requestId") + "  HTTP " + response.optInt("status") + "  " + response.optString("mimeType"));
            } else if ("Network.loadingFinished".equals(method) && params != null) {
                listener.onNetworkRecord("FINISHED " + params.optString("requestId") + "  " + params.optLong("encodedDataLength") + " B");
            } else if ("Network.loadingFailed".equals(method) && params != null) {
                listener.onNetworkRecord("FAILED " + params.optString("requestId") + "  " + params.optString("errorText"));
            }
        } catch (Exception ignored) { }
    }

    private void sendTextFrame(String text) throws Exception {
        sendFrame(0x1, text.getBytes(StandardCharsets.UTF_8));
    }

    private void sendFrame(int opcode, byte[] payload) throws Exception {
        ByteArrayOutputStream frame = new ByteArrayOutputStream();
        frame.write(0x80 | opcode);
        if (payload.length < 126) {
            frame.write(0x80 | payload.length);
        } else if (payload.length <= 65535) {
            frame.write(0x80 | 126);
            frame.write((payload.length >>> 8) & 0xff);
            frame.write(payload.length & 0xff);
        } else {
            frame.write(0x80 | 127);
            for (int shift = 56; shift >= 0; shift -= 8) frame.write((payload.length >>> shift) & 0xff);
        }
        byte[] mask = new byte[4]; new SecureRandom().nextBytes(mask); frame.write(mask);
        for (int i = 0; i < payload.length; i++) frame.write(payload[i] ^ mask[i % 4]);
        output.write(frame.toByteArray()); output.flush();
    }

    private String readTextFrame(InputStream in) throws Exception {
        while (true) {
            int first = in.read(); if (first < 0) return null;
            int second = in.read(); if (second < 0) return null;
            int opcode = first & 0x0f;
            long length = second & 0x7f;
            if (length == 126) length = readUnsignedShort(in);
            else if (length == 127) length = readLong(in);
            boolean masked = (second & 0x80) != 0;
            byte[] mask = masked ? readFully(in, 4) : null;
            if (length > 8 * 1024 * 1024) throw new IllegalStateException("Frame CDP demasiado grande");
            byte[] payload = readFully(in, (int) length);
            if (masked) for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
            if (opcode == 0x8) return null;
            // Antes un ping devolvía null y cerraba toda la conexión CDP, con lo
            // que el inspector dejaba de recibir eventos hasta reiniciar la app.
            // Ahora se responde pong y se sigue leyendo el siguiente frame.
            if (opcode == 0x9) { if (output != null) sendFrame(0xA, payload); continue; }
            return new String(payload, StandardCharsets.UTF_8);
        }
    }

    private String readHttpBody(InputStream in) throws Exception {
        String headers = readUntilHeaderEnd(in);
        int contentLength = 0;
        for (String line : headers.split("\r\n")) if (line.toLowerCase().startsWith("content-length:")) contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
        byte[] body = readFully(in, contentLength);
        return new String(body, StandardCharsets.UTF_8);
    }

    private String readUntilHeaderEnd(InputStream in) throws Exception {
        // Antes se hacía buffer.toString() por cada byte leído (O(n²) al
        // buscar el fin de cabecera); ahora se comprueban solo los últimos
        // 4 bytes con una ventana deslizante.
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int window = 0, current;
        while ((current = in.read()) >= 0) {
            buffer.write(current);
            window = (window << 8) | (current & 0xff);
            if (buffer.size() >= 4 && window == 0x0d0a0d0a) break;
        }
        return buffer.toString(StandardCharsets.US_ASCII.name());
    }

    private byte[] readFully(InputStream in, int length) throws Exception {
        byte[] result = new byte[length]; int offset = 0;
        while (offset < length) { int count = in.read(result, offset, length - offset); if (count < 0) throw new EOFException(); offset += count; }
        return result;
    }

    private int readUnsignedShort(InputStream in) throws Exception { return (in.read() << 8) | in.read(); }
    private long readLong(InputStream in) throws Exception { long result = 0; for (int i = 0; i < 8; i++) result = (result << 8) | (in.read() & 0xffL); return result; }
    private String randomKey() { byte[] bytes = new byte[16]; new SecureRandom().nextBytes(bytes); return Base64.encodeToString(bytes, Base64.NO_WRAP); }
    private String safeMessage(Exception error) { return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage(); }
}
