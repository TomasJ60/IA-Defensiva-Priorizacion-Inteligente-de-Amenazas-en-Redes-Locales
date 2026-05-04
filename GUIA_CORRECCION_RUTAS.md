# 🔧 GUÍA DE CORRECCIÓN - Rutas de Alertas, Activos y OSINT

## ✅ Problemas Corregidos

### 1. **Links en Templates (BASE)**
   - ✓ Corregidos todos los links para usar `{% url %}` en lugar de rutas hardcodeadas
   - Archivo: `web/monitoreo/templates/monitoreo/base_dashboard.html`
   - Beneficio: Los links ahora se generan dinámicamente usando nombres de rutas

### 2. **Decoradores de Autenticación (MEJORADO)**
   - ✓ Mejorado el decorador `@two_factor_required` para preservar la ruta original
   - Archivo: `web/monitoreo/views.py` (función `two_factor_required`)
   - Beneficio: Después de completar 2FA, el usuario es redirigido a su ruta original

## 🚀 Pasos para Acceder Correctamente

### Paso 1: Inicia Sesión
```
URL: http://127.0.0.1:8000/login/
Usuario: admin
Contraseña: AdminPassword123!
```

### Paso 2: Accede a las Secciones
Una vez autenticado, puedes acceder a:
- **Overview**: http://127.0.0.1:8000/ o http://127.0.0.1:8000/overview/
- **Alertas**: http://127.0.0.1:8000/alertas/
- **Activos**: http://127.0.0.1:8000/activos/
- **OSINT**: http://127.0.0.1:8000/osint/

## 📋 Configuración de Autenticación 2FA

Tu usuario necesita completar la configuración de 2FA (Autenticación de Dos Factores):

1. **Primera vez accediendo a las rutas protegidas:**
   - Serás redirigido a: `/2fa/setup/`
   - Escanea el código QR con Google Authenticator o similar
   - Ingresa el código de 6 dígitos

2. **Próximos accesos:**
   - Se te pedirá que verifiques el código 2FA
   - Ingresa el código actual de tu aplicación

## 🔍 Verificación de Rutas

Para verificar que todas las rutas están correctamente cargadas:

```bash
cd /home/tomas/Escritorio/proyectoU/proyecto
source .venv/bin/activate
python web/manage.py shell

# En el shell de Django:
from django.urls import get_resolver
resolver = get_resolver()
for pattern in resolver.url_patterns:
    if 'alertas' in str(pattern) or 'activos' in str(pattern) or 'osint' in str(pattern):
        print(pattern)
```

## 📝 Notas Técnicas

### Rutas Configuradas (monitoreo/urls.py):
```python
path('alertas/', views.dashboard_alertas, name='dashboard_alertas'),
path('activos/', views.dashboard_activos, name='dashboard_activos'),
path('osint/', views.dashboard_osint, name='dashboard_osint'),
```

### Decoradores Aplicados:
```python
@two_factor_required      # Requiere autenticación + 2FA
@require_soc_access       # Requiere rol SOC
@never_cache             # No cachear respuesta
```

### Roles de Acceso:
- **Superuser/Staff**: ✓ Acceso automático a todas las vistas
- **Usuarios Normales**: Necesitan ser asignados al grupo SOC

## ❓ Solución de Problemas

### Si ves "Page not found (404)"
1. ✓ Verifica que estés **autenticado** (iniciaste sesión)
2. ✓ Completó la configuración de **2FA**
3. ✓ Tu usuario tiene **acceso SOC**

### Si ves "403 Forbidden"
- Tu usuario no tiene permisos SOC
- Ejecuta: `python setup_user.py` para crear un usuario con permisos

### Si se te desconecta constantemente
- Los timeouts de sesión están configurados en `settings.py`:
  - Inactividad: 15 minutos (900 segundos)
  - Máximo: 8 horas (28800 segundos)

## 🛠️ Archivos Modificados

1. **web/monitoreo/templates/monitoreo/base_dashboard.html**
   - Links ahora usan `{% url 'name' %}`

2. **web/monitoreo/views.py**
   - Decorador `two_factor_required` mejorado

3. **setup_user.py** (NUEVO)
   - Script para crear usuarios de prueba

## ✨ Mejoras Futuras Recomendadas

1. Considerar usar un middleware de redirección más robusto
2. Agregar mensajes de feedback cuando se redirige a 2FA
3. Implementar "Remember Device" para 2FA

---

**Estado**: ✅ Todas las rutas están funcionando correctamente
**Fecha**: 3 de mayo de 2026
