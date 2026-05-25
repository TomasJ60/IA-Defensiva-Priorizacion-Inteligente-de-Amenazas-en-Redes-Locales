# IA Defensiva: Priorizacion Inteligente de Amenazas en Redes Locales

Sistema de monitoreo defensivo para redes locales con captura de eventos, priorizacion de alertas, enriquecimiento OSINT y panel web para analisis operativo.

Esta version del repositorio contiene solo el codigo y los archivos que forman parte del flujo funcional del proyecto. Tambien incluye el paquete Debian generado para despliegue rapido:

- `agente-ia-defensiva_1.0.0_all.deb`

## Componentes incluidos

- Dashboard web en Django para alertas, redes, activos y analisis.
- Agente de ingesta en `src/agente.py`.
- Motor IA/XAI en `src/ia_motor.py`.
- Enriquecimiento OSINT integrado.
- Scripts de instalacion y arranque.
- Archivos `systemd` y empaquetado Debian.

## Estructura principal

- `web/`: aplicacion web Django.
- `src/`: agente, motor IA y utilidades operativas.
- `suricata/`: reglas locales.
- `debian/`: definicion del paquete `.deb`.
- `agente-ia-defensiva_1.0.0_all.deb`: paquete listo para instalar en Debian/Ubuntu.

## Ejecucion local

```bash
source .venv/bin/activate
cd web
python manage.py runserver
```

En otra terminal puedes ejecutar el agente:

```bash
source .venv/bin/activate
cd src
python agente.py
```

## Instalacion mediante paquete Debian

Este paquete esta pensado para distribuciones basadas en Debian o Ubuntu.

```bash
sudo dpkg -i agente-ia-defensiva_Version_Final.deb
sudo apt-get install -f
```

Servicios instalados:

- `agente-ia-defensiva-web`
- `agente-ia-defensiva-agent`
- `agente-ia-defensiva-ia`

## Configuracion

- Usa `.env.example` como referencia para crear tu configuracion local.
- El archivo `.env` real no se incluye en el repositorio.

## Nota

Este repositorio fue depurado para conservar solo la parte operativa del proyecto y evitar archivos temporales, entornos virtuales, caches y componentes legacy que no participan en la ejecucion actual.
