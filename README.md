# BrowserDebug

**Navegador Android con inspector CDP embebido, convertido en herramienta de pruebas de seguridad web.** Prueba XSS, SQLi, path traversal y redirección abierta directamente desde el teléfono, solo en sistemas propios o con autorización expresa.

[![Android CI](https://github.com/hubgunter4-ops/BrowserDebug/actions/workflows/android-ci.yml/badge.svg)](https://github.com/hubgunter4-ops/BrowserDebug/actions/workflows/android-ci.yml)
[![Release v3.0](https://img.shields.io/github/v/release/hubgunter4-ops/BrowserDebug)](https://github.com/hubgunter4-ops/BrowserDebug/releases/tag/v3.0)

## Descargar

[**debug-browser-v3.0.apk**](https://github.com/hubgunter4-ops/BrowserDebug/releases/download/v3.0/debug-browser-v3.0.apk) — compilación debug (no firmada para producción). Instálala permitiendo «instalar apps desconocidas» para el navegador o el gestor de archivos.

## Qué hace

BrowserDebug abre cualquier página en un WebView con el protocolo CDP y te deja inspeccionarla y atacarla desde el propio teléfono:

| Pestaña | Qué hace |
|---|---|
| **Consola** | Mensajes de consola, errores JS y eventos CDP. |
| **Solicitudes** | Registro de red (método, URL, estado, tipo) con detalle por petición. |
| **Repetidor** | Edita y reenvía peticiones (método, URL, cabeceras, cuerpo) con las cookies de sesión y el User-Agent del WebView; decodificador Base64, URL, entidades HTML y hexadecimal. Incluye el **Intruso**: ataca un parámetro con listas XSS, SQLi, path traversal, redirección abierta o personalizada, una petición por payload, y marca REFLEJADO, ERROR SQL y TRAVERSAL. |
| **OWASP** | Cobertura, canario, caracteres críticos, WAF, CSP y cookies; **escaneo automático** que encadena descubrir entradas, canario, payloads por contexto, sondeo de caracteres, CSP/cookies, WAF, SQLi, traversal y redirección abierta; autollenado de formularios. |
| **JS y bundles** | Evaluar JS, Resource Timing, errores JS, análisis de sumideros (`innerHTML`, `eval(`, `document.write`…), generador de payloads desde bundles y **biblioteca de 127 payloads XSS** curados (ver Créditos). |
| **Recon** | DNS, **mapa del sitio** (rastrea los enlaces del mismo dominio), detección de tecnologías (servidor, CMS, librerías) y almacenamiento local. |
| **VPN** | Abre Tailscale, Cloudflare One Agent o 1.1.1.1 para tunelizar el tráfico. |
| **Reporte** | Reúne los hallazgos del escaneo y del Intruso con fecha y URL; copiar, compartir o exportar. |

## Uso responsable

Esta herramienta es para **pruebas de seguridad autorizadas**: úsala solo en tus propios sitios o en sistemas donde tengas autorización expresa por escrito. Probar sitios ajenos sin permiso puede ser ilegal. Los payloads de exfiltración y escalado necesitan tu propio servidor de escucha (`https://TU-SERVIDOR/` es solo un marcador) y, en el caso de los de hakluke, sesión de administrador en el CMS objetivo.

## Compilar desde el código

Requisitos: Android SDK con plataforma 35, JDK 17 y Gradle 8.7 (wrapper incluido).

```bash
./gradlew assembleDebug
```

El APK queda en `app/build/outputs/apk/debug/app-debug.apk`. Las compilaciones de GitHub Actions (`Android CI` en cada push a `main` y `Android Release` en cada tag `v*`) producen el mismo APK.

## Créditos y licencias

- **Biblioteca de payloads XSS (127):** curada de [theWeborion/xss-bypass-techniques](https://github.com/theWeborion/xss-bypass-techniques) (sin licencia declarada), [pgaijin66/XSS-Payloads](https://github.com/pgaijin66/XSS-Payloads) (**GPL-3.0**) y [hakluke/weaponised-XSS-payloads](https://github.com/hakluke/weaponised-XSS-payloads) (sin licencia declarada).
- **Animaciones Lottie:** LK Jing, Luis Pérez y Subho Mondal, bajo la Lottie Simple License (ver `LOTTIE-LICENSES.md`).
- **Código original:** licencia propietaria, ver `LICENSE-COMERCIAL.txt` (plantilla con campos pendientes de completar por el titular) y `NOTICE-TERCEROS.md`.
- La app no incorpora Burp Suite (aplicación de escritorio propietaria sin SDK móvil). Para usar el Burp de PC con el teléfono, configura el proxy Wi-Fi y su certificado CA; eso exige una configuración de seguridad de red para certificados de usuario.

## Estado

**v3.0** (versionCode 13) — de depurador a herramienta de pruebas de seguridad: 8 pestañas, Intruso, mapa del sitio, escaneo ampliado y reporte. Historial de versiones en [Releases](https://github.com/hubgunter4-ops/BrowserDebug/releases).
