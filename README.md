# Introducción

El mejor script de instalación y gestión de Xray de un solo comando

# Características

- Instalación rápida
- Extremadamente fácil de usar
- Cero curva de aprendizaje
- TLS automático
- Simplificación de todos los procesos
- Bloqueo de BT
- Bloqueo de IPs chinas
- Operaciones mediante API
- Compatible con comandos de Xray
- Poderosos parámetros rápidos
- Soporte para todos los protocolos comunes
- Agregar VLESS-REALITY con un comando (por defecto)
- Agregar Shadowsocks 2022 con un comando
- Agregar VMess-(TCP/mKCP) con un comando
- Agregar VMess-(WS/gRPC)-TLS con un comando
- Agregar VLESS-(WS/gRPC/XHTTP)-TLS con un comando
- Agregar Trojan-(WS/gRPC)-TLS con un comando
- Agregar puertos dinámicos VMess-(TCP/mKCP) con un comando
- Habilitar BBR con un comando
- Cambiar sitio web de camuflaje con un comando
- Cambiar (puerto/UUID/contraseña/dominio/ruta/método de cifrado/SNI/puerto dinámico/etc...) con un comando
- Y mucho más...

# Filosofía de diseño

La filosofía de diseño es: **Alta eficiencia, súper rápido, extremadamente fácil de usar**

El script está basado en las necesidades de uso del autor, diseñado con el núcleo de **ejecución simultánea de múltiples configuraciones**

Y está especialmente optimizado para las cuatro funciones comunes: agregar, cambiar, ver y eliminar

Solo necesitas un comando para completar operaciones como agregar, cambiar, ver, eliminar, etc.

¡Por ejemplo, agregar una configuración toma menos de 1 segundo! ¡Se completa instantáneamente! ¡Otras operaciones también!

Los parámetros del script son muy eficientes y súper fáciles de usar, por favor domina el uso de los parámetros

# Documentación

Instalación y uso: https://233boy.com/xray/xray-script/

# Ayuda

Uso: xray [opciones]... [argumentos]...

Básico:
   v, version                                      Mostrar versión actual
   ip                                              Devolver IP del host actual
   pbk                                             Equivalente a xray x25519
   get-port                                        Devolver un puerto disponible
   ss2022                                          Devolver una contraseña usable para Shadowsocks 2022

General:
   a, add [protocolo] [args... | auto]            Agregar configuración
   c, change [nombre] [opción] [args... | auto]   Cambiar configuración
   d, del [nombre]                                Eliminar configuración**
   i, info [nombre]                               Ver configuración
   qr [nombre]                                    Información de código QR
   url [nombre]                                   Información de URL
   log                                            Ver registros
   logerr                                         Ver registros de errores

Cambios:
   dp, dynamicport [nombre] [inicio | auto] [fin] Cambiar puerto dinámico
   full [nombre] [...]                            Cambiar múltiples parámetros
   id [nombre] [uuid | auto]                      Cambiar UUID
   host [nombre] [dominio]                        Cambiar dominio
   port [nombre] [puerto | auto]                  Cambiar puerto
   path [nombre] [ruta | auto]                    Cambiar ruta
   passwd [nombre] [contraseña | auto]            Cambiar contraseña
   key [nombre] [Clave privada | auto] [Clave pública] Cambiar claves
   type [nombre] [tipo | auto]                    Cambiar tipo de camuflaje
   method [nombre] [método | auto]                Cambiar método de cifrado
   sni [nombre] [ ip | dominio]                   Cambiar serverName
   seed [nombre] [semilla | auto]                 Cambiar semilla mKCP
   new [nombre] [...]                             Cambiar protocolo
   web [nombre] [dominio]                         Cambiar sitio web de camuflaje

Avanzado:
   dns [...]                                      Configurar DNS
   dd, ddel [nombre...]                           Eliminar múltiples configuraciones**
   fix [nombre]                                   Reparar una configuración
   fix-all                                        Reparar todas las configuraciones
   fix-caddyfile                                  Reparar Caddyfile
   fix-config.json                                Reparar config.json

Gestión:
   un, uninstall                                  Desinstalar
   u, update [core | sh | dat | caddy] [ver]      Actualizar
   U, update.sh                                   Actualizar script
   s, status                                      Estado de ejecución
   start, stop, restart [caddy]                   Iniciar, Detener, Reiniciar
   t, test                                        Probar ejecución
   reinstall                                      Reinstalar script

Pruebas:
   client [nombre]                                Mostrar JSON para cliente, solo como referencia
   debug [nombre]                                 Mostrar información de debug, solo como referencia
   gen [...]                                      Equivalente a add, pero solo muestra contenido JSON, no crea archivo, para pruebas
   genc [nombre]                                  Mostrar parte JSON para cliente, solo como referencia
   no-auto-tls [...]                              Equivalente a add, pero deshabilita configuración automática TLS, para protocolos *TLS relacionados
   xapi [...]                                     Equivalente a xray api, pero API backend usa el servicio Xray actualmente en ejecución

Otros:
   bbr                                            Habilitar BBR, si es compatible
   bin [...]                                      Ejecutar comando Xray, por ejemplo: xray bin help
   api, x25519, tls, run, uuid  [...]             Compatible con comandos Xray
   h, help                                        Mostrar esta ayuda

Use con precaución del, ddel, esta opción eliminará la configuración directamente; sin confirmación
Reportar problemas) https://github.com/233boy/xray/issues
Documentación(doc) https://233boy.com/xray/xray-script/


# Instalación

```bash
bash -c "$(wget -qO- https://github.com/audiopsicotiko/xray/raw/master/install.sh)"

#  Desinstalacion
xray uninstall

