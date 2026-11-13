# Cliente CDP incrustado para la vista de red

`CdpNetworkClient` conecta únicamente en builds debug al socket abstracto `webview_devtools_remote_<pid>` creado por WebView. Primero consulta `/json/list`, obtiene el path del target page y abre el handshake WebSocket sobre un segundo `LocalSocket`. Después habilita `Network`, `Page` y `Runtime` y transforma estos eventos CDP en registros separados para la vista **Solicitudes**:

- `Network.requestWillBeSent`: método, URL y `requestId`.
- `Network.responseReceived`: status HTTP y MIME type.
- `Network.loadingFinished`: bytes recibidos.
- `Network.loadingFailed`: error de carga.

Los registros CDP se mantienen en `cdpNetworkRecords` y no se mezclan con los registros legacy de `WebViewClient`. La vista los presenta en una sección independiente titulada `Eventos CDP Network`. El estado de conexión se publica en la consola como `CDP conectado` o `CDP no disponible: ...`.

El cliente se inicia solamente cuando `BuildConfig.DEBUG` es verdadero y se detiene en `onDestroy`. En producción no se abre el socket de depuración ni se ejecutan comandos CDP.

## Opciones para construir el APK

### GitHub Actions — recomendado para el APK debug

Cada push a `main` ejecuta el workflow de Android CI, compila `assembleDebug`, verifica la existencia del APK y trata de subirlo como artifact. La subida puede quedar bloqueada temporalmente por la cuota de artifacts, pero no invalida una compilación correcta.

```bash
git push origin main
```

### GitHub Release — recomendado para distribuir una actualización

El workflow de release compila el APK y lo adjunta a una release cuando se publica un tag `v*`.

```bash
git tag v1.0.0
git push origin v1.0.0
```

### Compilación local con Gradle

En una máquina con JDK 17, Android SDK Platform 35 y Build-Tools 34.0.0:

```bash
./gradlew assembleDebug
```

El resultado queda en `app/build/outputs/apk/debug/app-debug.apk`.

### Android Studio

Abrir el repositorio como proyecto Gradle, seleccionar la variante `debug` y usar **Build > Build APK(s)**. Para pruebas CDP debe instalarse la variante debug; una variante release mantiene el cliente desactivado.

### APK firmado de producción

Para distribución real se debe crear una configuración `signingConfig` con un keystore privado, usar `assembleRelease` y no incluir secretos en GitHub. La depuración WebView y el cliente CDP permanecen desactivados en release.
