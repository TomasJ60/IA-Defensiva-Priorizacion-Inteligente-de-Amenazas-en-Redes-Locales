from django.core.management.base import BaseCommand
from monitoreo.models import SuricataConfig
import subprocess
import os
import ipaddress
from pathlib import Path

class Command(BaseCommand):
    help = 'Aplica la configuración de Suricata desde la base de datos'

    def detect_active_interfaces(self):
        interfaces = []
        try:
            result = subprocess.run(
                ['ip', '-o', 'link', 'show', 'up'],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        name = parts[1].strip().split('@')[0]
                        if name and name != 'lo':
                            interfaces.append(name)
        except Exception:
            interfaces = []

        if not interfaces:
            try:
                net_dir = Path('/sys/class/net')
                interfaces = [p.name for p in net_dir.iterdir() if p.is_dir() and p.name != 'lo']
            except Exception:
                interfaces = []

        return interfaces

    def validate_interfaces(self, interfaces):
        if not interfaces:
            return []
        active = set(self.detect_active_interfaces())
        return [iface for iface in interfaces if iface in active]

    def get_interface_networks(self, interfaces):
        networks = []
        for iface in interfaces:
            try:
                result = subprocess.run(
                    ['ip', '-o', '-f', 'inet', 'addr', 'show', iface],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                if result.returncode != 0:
                    continue

                for line in result.stdout.splitlines():
                    parts = line.split()
                    for part in parts:
                        if '/' in part:
                            try:
                                networks.append(str(ipaddress.ip_network(part, strict=False)))
                            except ValueError:
                                continue
            except Exception:
                continue

        # Preserve ordering and uniqueness
        seen = set()
        unique_networks = []
        for net in networks:
            if net not in seen:
                seen.add(net)
                unique_networks.append(net)

        return unique_networks

    def apply_home_net(self, suricata_config, interfaces):
        if 'vars' not in suricata_config:
            suricata_config['vars'] = {}
        if 'address-groups' not in suricata_config['vars']:
            suricata_config['vars']['address-groups'] = {}

        networks = self.get_interface_networks(interfaces)
        if not networks:
            return False, "No se pudieron detectar redes para HOME_NET"

        if len(networks) == 1:
            suricata_config['vars']['address-groups']['HOME_NET'] = networks[0]
        else:
            suricata_config['vars']['address-groups']['HOME_NET'] = networks

        return True, f"HOME_NET actualizado a {suricata_config['vars']['address-groups']['HOME_NET']}"

    def apply_with_yaml(self, config_path, interfaces):
        """Intenta aplicar la configuración usando PyYAML"""
        try:
            import yaml
        except ImportError:
            return False, "PyYAML no está instalado"

        try:
            with open(config_path, 'r') as f:
                suricata_config = yaml.safe_load(f)

            if 'af-packet' not in suricata_config:
                suricata_config['af-packet'] = []

            suricata_config['af-packet'] = []

            for iface in interfaces:
                suricata_config['af-packet'].append({
                    'interface': iface,
                    'cluster-id': 99,
                    'cluster-type': 'cluster_flow',
                    'defrag': True,
                })

            home_net_ok, home_net_message = self.apply_home_net(suricata_config, interfaces)
            if not home_net_ok:
                return False, home_net_message

            with open(config_path, 'w') as f:
                yaml.dump(suricata_config, f, default_flow_style=False)

            return True, f"YAML configurado correctamente; {home_net_message}"
        except Exception as e:
            return False, f"Error con YAML: {e}"

    def apply_with_sed(self, config_path, interfaces):
        """Fallback: intenta aplicar usando sed (si PyYAML falla)"""
        try:
            # Crear backup
            result = subprocess.run(['sudo', 'cp', config_path, f'{config_path}.bak'],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"No se pudo crear backup: {result.stderr}"

            # Leer el archivo
            result = subprocess.run(['sudo', 'cat', config_path],
                                  capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"No se pudo leer {config_path}"

            content = result.stdout

            # Buscar la sección af-packet
            if 'af-packet:' not in content:
                return False, "Sección af-packet no encontrada en configuración"

            # Reemplazar interfaces (versión simple)
            lines = content.split('\n')
            new_lines = []
            in_af_packet = False
            skip_until_next_section = False

            for i, line in enumerate(lines):
                if 'af-packet:' in line:
                    in_af_packet = True
                    new_lines.append(line)
                    skip_until_next_section = True
                    # Agregar las nuevas interfaces
                    for j, iface in enumerate(interfaces):
                        new_lines.append(f'  - interface: {iface}')
                        new_lines.append('    cluster-id: 99')
                        new_lines.append('    cluster-type: cluster_flow')
                        new_lines.append('    defrag: true')
                elif skip_until_next_section and line.strip() and not line.startswith('  - '):
                    if ':' in line and not line.startswith('    '):
                        skip_until_next_section = False
                        in_af_packet = False
                    else:
                        continue
                    new_lines.append(line)
                else:
                    new_lines.append(line)

            new_content = '\n'.join(new_lines)

            # Escribir de vuelta
            result = subprocess.run(['sudo', 'tee', config_path],
                                  input=new_content, capture_output=True, text=True)
            if result.returncode != 0:
                return False, f"Error escribiendo config: {result.stderr}"

            return True, "Configuración aplicada con sed"
        except Exception as e:
            return False, f"Error con sed: {e}"

    def handle(self, *args, **options):
        try:
            config = SuricataConfig.objects.first()
            interfaces = []

            if config and config.is_active:
                interfaces = config.interface_list
                valid_interfaces = self.validate_interfaces(interfaces)
                if valid_interfaces:
                    interfaces = valid_interfaces
                else:
                    detected = self.detect_active_interfaces()
                    if detected:
                        self.stdout.write(self.style.WARNING('Las interfaces configuradas no son válidas en este equipo. Se usarán interfaces detectadas: ' + ', '.join(detected)))
                        interfaces = detected
                    else:
                        self.stdout.write(self.style.ERROR('No se pudieron detectar interfaces de red activas. Revisa la configuración en el dashboard.'))
                        return
            else:
                if config and not config.is_active:
                    self.stdout.write(self.style.WARNING('Configuración de Suricata inactiva. Activa el monitoreo en el dashboard.'))
                    return
                detected = self.detect_active_interfaces()
                if not detected:
                    self.stdout.write(self.style.ERROR('No se encontraron interfaces de red activas. Revisa la configuración del equipo.'))
                    return
                self.stdout.write(self.style.WARNING('No hay configuración de Suricata activa. Se usarán interfaces detectadas: ' + ', '.join(detected)))
                interfaces = detected

            self.stdout.write(f'Aplicando configuración para interfaces: {interfaces}')

            config_path = '/etc/suricata/suricata.yaml'
            
            if not os.path.exists(config_path):
                self.stdout.write(self.style.ERROR(f'Archivo de configuración no encontrado: {config_path}'))
                return

            # Intentar con YAML primero
            success, message = self.apply_with_yaml(config_path, interfaces)
            if not success:
                self.stdout.write(self.style.WARNING(f'YAML: {message}. Intentando con sed...'))
                success, message = self.apply_with_sed(config_path, interfaces)

            if success:
                self.stdout.write(f'✅ {message}')
            else:
                self.stdout.write(self.style.ERROR(f'❌ {message}'))
                return

            # Reiniciar Suricata
            result = subprocess.run(['sudo', 'systemctl', 'restart', 'suricata'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.stdout.write(self.style.SUCCESS('✅ Suricata reiniciado correctamente'))
            else:
                self.stdout.write(self.style.ERROR(f'❌ Error reiniciando Suricata: {result.stderr}'))

        except subprocess.TimeoutExpired:
            self.stdout.write(self.style.ERROR('Timeout reiniciando Suricata'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error aplicando configuración: {e}'))