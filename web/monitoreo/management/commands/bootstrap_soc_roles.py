from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

from monitoreo.roles import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER


class Command(BaseCommand):
    help = "Crea los grupos base de acceso para el dashboard SOC."

    def handle(self, *args, **options):
        for role in (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER):
            _, created = Group.objects.get_or_create(name=role)
            status = "creado" if created else "ya existia"
            self.stdout.write(self.style.SUCCESS(f"Grupo {role}: {status}"))

        self.stdout.write("")
        self.stdout.write("Roles disponibles:")
        self.stdout.write(f"- {ROLE_ADMIN}: acceso total al dashboard y gestion de activos")
        self.stdout.write(f"- {ROLE_ANALYST}: acceso al dashboard y gestion de activos")
        self.stdout.write(f"- {ROLE_VIEWER}: acceso de solo lectura al dashboard")
