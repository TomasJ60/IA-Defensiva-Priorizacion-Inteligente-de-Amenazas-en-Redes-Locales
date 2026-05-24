import os

# CONFIGURACIÓN: Carpetas y archivos que NO queremos enviar (para no saturar a Claude)
IGNORE_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'env', 'dist', 'build', '.idea', '.vscode'}
IGNORE_FILES = {'empaquetador.py', 'codigo_para_claude.txt', 'package-lock.json', 'yarn.lock', '.DS_Store'}
EXTENSIONES_VALIDAS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.c', '.cpp', '.java', '.php', '.sql', '.md'}

def empaquetar_codigo(ruta_proyecto, archivo_salida):
    with open(archivo_salida, 'w', encoding='utf-8') as f_out:
        for raiz, carpetas, archivos in os.walk(ruta_proyecto):
            # Filtrar carpetas ignoradas
            carpetas[:] = [d for d in carpetas if d not in IGNORE_DIRS]
            
            for nombre_archivo in archivos:
                if nombre_archivo in IGNORE_FILES:
                    continue
                
                # Solo leer archivos de texto con extensiones de código
                if any(nombre_archivo.endswith(ext) for ext in EXTENSIONES_VALIDAS):
                    ruta_completa = os.path.join(raiz, nombre_archivo)
                    ruta_relativa = os.path.relpath(ruta_completa, ruta_proyecto)
                    
                    try:
                        with open(ruta_completa, 'r', encoding='utf-8') as f_in:
                            contenido = f_in.read()
                            f_out.write(f"\n{'='*50}\n")
                            f_out.write(f"ARCHIVO: {ruta_relativa}\n")
                            f_out.write(f"{'='*50}\n\n")
                            f_out.write(contenido)
                            f_out.write("\n")
                    except Exception as e:
                        print(f"No se pudo leer {ruta_relativa}: {e}")

    print(f"¡Listo! Todo tu código se ha guardado en: {archivo_salida}")

if __name__ == "__main__":
    empaquetar_codigo('.', 'codigo_chat.txt')