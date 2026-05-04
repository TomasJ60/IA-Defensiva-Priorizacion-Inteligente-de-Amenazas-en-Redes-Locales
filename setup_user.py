#!/usr/bin/env python
"""
Script para configurar un usuario de prueba con acceso SOC
Uso: python setup_user.py
"""
import os
import sys
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ia_defensiva_soc.settings')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

django.setup()

from django.contrib.auth.models import User, Group
from monitoreo.roles import assign_soc_role, ROLE_ADMIN

def main():
    # Crear o obtener un usuario de prueba
    username = "admin"
    email = "admin@test.local"
    password = "AdminPassword123!"
    
    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            'email': email,
            'is_staff': True,
            'is_superuser': True,
        }
    )
    
    if created:
        user.set_password(password)
        user.save()
        print(f"✓ Usuario creado: {username}")
        print(f"  Contraseña: {password}")
    else:
        print(f"✓ Usuario ya existe: {username}")
        # Actualizar contraseña si es necesario
        user.set_password(password)
        user.save()
        print(f"  Contraseña actualizada: {password}")
    
    # Asignar rol SOC si no es superuser
    if not user.is_superuser:
        try:
            assign_soc_role(user, ROLE_ADMIN)
            print(f"✓ Rol SOC asignado: {ROLE_ADMIN}")
        except Exception as e:
            print(f"✗ Error al asignar rol: {e}")
    else:
        print(f"✓ Usuario es superuser, tiene acceso automático")
    
    print("\n=== Instrucciones ===")
    print(f"1. Accede a: http://127.0.0.1:8000/login/")
    print(f"2. Usuario: {username}")
    print(f"3. Contraseña: {password}")
    print(f"4. Luego accede a:")
    print(f"   - http://127.0.0.1:8000/alertas/")
    print(f"   - http://127.0.0.1:8000/activos/")
    print(f"   - http://127.0.0.1:8000/osint/")

if __name__ == '__main__':
    main()
