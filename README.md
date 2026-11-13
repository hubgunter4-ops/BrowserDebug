# BrowserDebug

Navegador Android con inspector CDP embebido, convertido en herramienta de pruebas de seguridad web.

## Descargar

[debug-browser-v3.0.apk](https://github.com/hubgunter4-ops/BrowserDebug/releases/download/v3.0/debug-browser-v3.0.apk) — compilación debug (no firmada para producción).

## Funciones

| Pestaña | Qué hace |
|---|---|
| Consola | Mensajes de consola, errores JS y eventos CDP. |
| Solicitudes | Registro de red (método, URL, estado, tipo). |
| Repetidor | Edita y reenvía peticiones; decodificador Base64, URL, HTML y Hex. Incluye el Intruso, que ataca un parámetro con listas XSS, SQLi, path traversal, redirección abierta o personalizada. |
| OWASP | Cobertura, canario, caracteres críticos, WAF, CSP y cookies; escaneo automático y autollenado de formularios. |
| JS y bundles | Evaluar JS, errores JS, análisis de sumideros y biblioteca de 127 payloads XSS. |
| Recon | DNS, mapa del sitio, detección de tecnologías y almacenamiento local. |
| VPN | Abre Tailscale, Cloudflare One Agent o 1.1.1.1. |
| Reporte | Hallazgos del escaneo y del Intruso; copiar, compartir o exportar. |

## Compilar

```bash
./gradlew assembleDebug
```

Requisitos: Android SDK con plataforma 35 y JDK 17. El APK queda en `app/build/outputs/apk/debug/app-debug.apk`.

## Créditos

Payloads XSS de theWeborion/xss-bypass-techniques, pgaijin66/XSS-Payloads (GPL-3.0) y hakluke/weaponised-XSS-payloads. Animaciones Lottie de LK Jing, Luis Pérez y Subho Mondal (Lottie Simple License). Código original © hubgunter4-ops, todos los derechos reservados.
