# Agente IA - Instalación completa

Este proyecto ahora incluye una instalación automatizada para Linux y un arranque rápido del dashboard web.

## Qué hace el instalador

- Instala los paquetes necesarios de Python y Suricata.
- Instala PostgreSQL y crea la base de datos definida en `.env`.
- Crea `.env` desde `.env.example` si no existe.
- Instala las dependencias de Python en `.venv`.
- Ejecuta las migraciones de Django.
- Copia `suricata/local.rules` a `/etc/suricata/rules/local.rules`.
- Actualiza la configuración de Suricata para incluir `local.rules`.
- Trata de actualizar reglas con `suricata-update` cuando esté disponible.

## Instalación en Linux

Ejecuta el instalador desde la carpeta raíz del proyecto:

```bash
sudo ./install.sh
```

Si `sudo` no está disponible, ejecuta el script como root.

## Instalador avanzado: bootstrap y paquete

### Crear un paquete para compartir

Desde el proyecto original, crea un paquete tar.gz con:

```bash
./package-release.sh
```

Ese comando generará un archivo como `agente-ia-release-*.tar.gz`.

### Instalar en otra máquina Linux

Copia el paquete tar.gz y `bootstrap.sh` al equipo destino. Luego ejecuta:

```bash
sudo ./bootstrap.sh --archive agente-ia-release-*.tar.gz
```

Si tienes el paquete disponible en una URL pública, también puedes usar:

```bash
sudo ./bootstrap.sh --url https://example.com/agente-ia-release.tar.gz
```
### Paquete Debian `.deb`

También puedes crear el paquete Debian directamente con:

```bash
./build-deb.sh
```

Esto generará un archivo:

```bash
agente-ia_1.0.0_all.deb
```

Para instalarlo en otro equipo:

```bash
sudo dpkg -i agente-ia_1.0.0_all.deb
sudo apt-get install -f
```

El paquete `agente-ia` instala:

- el proyecto en `/opt/agente-ia`
- el servicio systemd `agente-ia`
- PostgreSQL y Suricata como dependencias
- el entorno virtual y las dependencias Python
- reglas locales de Suricata en `/etc/suricata/rules/local.rules`
### ¿Qué hace el bootstrap?

- extrae el proyecto en un directorio destino
- ejecuta `install.sh` automáticamente
- instala Suricata, PostgreSQL y las dependencias Python
- configura el servicio systemd para que el dashboard arranque solo

## Inicio del dashboard

Después de la instalación, inicia el servidor web con:

```bash
./start.sh
```

El servidor Django quedará disponible en:

```text
http://127.0.0.1:8000
```

## Credenciales iniciales de acceso

Al instalar el proyecto, el instalador crea automáticamente un usuario administrador inicial si no existe uno.

- Usuario: `admin`
- Contraseña: `admin123`
- Correo: `admin@example.com`

Estos valores pueden modificarse en el archivo `.env` antes de ejecutar `install.sh` o durante la instalación del paquete Debian con las variables:

```bash
ADMIN_USERNAME=miadmin
ADMIN_PASSWORD=mi_clave_segura
ADMIN_EMAIL=admin@midominio.local
```

Si prefieres cambiar la contraseña después de la instalación, ejecuta:

```bash
cd /opt/agente-ia
.source .venv/bin/activate
python web/manage.py changepassword admin
```

Si tu entorno gráfico tiene `xdg-open`, el script intentará abrir esa URL automáticamente.

## Configuración de Suricata

- Las interfaces de red se detectan automáticamente en el dashboard de Suricata.
- El sistema sugiere interfaces activas y las aplica directamente.
- El archivo `suricata/local.rules` se usa para reglas locales.
- Puedes agregar reglas personalizadas en `suricata/local.rules`.

## Tráfico específico y reglas

- El proyecto está diseñado para que Suricata se concentre en la red configurada por `HOME_NET`.
- El dashboard y la configuración usan solo las interfaces activas que detecte el equipo.
- Añade reglas locales específicas en `suricata/local.rules` para filtrar solo el tráfico que te interesa.

## Pruebas y validación

Este proyecto admite pruebas de:

- criticidad (alertas clasificadas según gravedad)
- OSINT (integración con proveedores externos)
- explicabilidad (registrando decisiones e indicadores)

Para que el sistema funcione bien, debes:

1. Instalar con `sudo ./install.sh`.
2. Iniciar con `./start.sh`.
3. Configurar Suricata en el dashboard.
4. Añadir reglas específicas en `suricata/local.rules`.

## Nota

Windows no está cubierto por este instalador. Si deseas soporte para Windows, podemos crear un instalador independiente o usar contenedores. Linux es el entorno recomendado para la instalación completa.
