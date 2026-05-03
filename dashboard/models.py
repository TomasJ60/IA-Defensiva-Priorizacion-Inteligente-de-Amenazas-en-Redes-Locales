from django.db import models

class Alerta(models.Model):
    # Definimos las columnas que ya tienes en tu base de datos
    fecha = models.DateTimeField(null=True, blank=True)
    ip_origen = models.CharField(max_length=50, null=True, blank=True)
    ip_destino = models.CharField(max_length=50, null=True, blank=True)
    firma = models.TextField(null=True, blank=True)
    severidad = models.IntegerField(null=True, blank=True)
    reputacion_osint = models.IntegerField(null=True, blank=True)
    prioridad_ia = models.FloatField(null=True, blank=True)

    class Meta:
        managed = False # Le dice a Django: "No crees la tabla, ya existe"
        db_table = 'alertas' # El nombre exacto de tu tabla en PostgreSQL