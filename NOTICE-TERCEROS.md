# Avisos de terceros, licencias y permisos

## Código de la aplicación

El código original de este proyecto está sujeto a la plantilla de licencia propietaria incluida en [`LICENSE-COMERCIAL.txt`](LICENSE-COMERCIAL.txt). Antes de distribuir o vender la aplicación, el titular de derechos debe completar los campos pendientes y formalizar/revisar la licencia con asesoría legal. La plantilla por sí sola no concede derechos de distribución a terceros.

## Android SDK y Android System WebView

La aplicación se compila usando Android SDK y se ejecuta sobre Android System WebView/Chromium. Esos componentes pertenecen a sus respectivos titulares y conservan sus propias licencias, avisos de copyright y condiciones. No se redistribuyen dentro del APK como bibliotecas de la aplicación. El SDK de compilación se usa únicamente durante el build.

## Dependencias de aplicación

El módulo `app` no declara bibliotecas externas en Gradle. Las dependencias de compilación del Android Gradle Plugin y del SDK se obtienen durante el build y deben revisarse nuevamente si se agregan dependencias futuras.

## Permisos del manifiesto

- `INTERNET`: permite que el WebView cargue páginas y recursos web.
- `ACCESS_NETWORK_STATE`: permiso normal para consultar el estado de conectividad; no muestra un diálogo de permisos al usuario.

La versión actual no solicita permisos runtime peligrosos como ubicación, cámara, micrófono, contactos, almacenamiento o notificaciones. Si se implementan descargas, multimedia, geolocalización u otras funciones, deberán añadirse sus permisos, explicación de uso y flujo de consentimiento correspondientes.

`android:usesCleartextTraffic="false"` mantiene bloqueadas las conexiones HTTP sin cifrar por defecto. Cualquier excepción futura debe justificarse y configurarse mediante una política de seguridad de red revisada.
