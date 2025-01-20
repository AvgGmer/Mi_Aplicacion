import sys
import os

# Añadir la ruta del entorno virtual (ajusta esta ruta según tu entorno)
sys.path.insert(0, '/home/newlunaq/virtualenv/app/3.9/lib/python3.9/site-packages')

# Añadir la ruta del proyecto
sys.path.insert(0, '/home/newlunaq/app')

# Cargar las variables de entorno si existe un archivo .env
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join('/home/newlunaq/app', '.env'))
except ImportError:
    pass  # dotenv no es obligatorio, ignora si no está disponible

# Importar la aplicación Flask
try:
    from Mail import app as application
except ImportError as e:
    raise ImportError(f"Error al importar la aplicación Flask: {e}. Verifica que el módulo 'Mail' y el objeto 'app' existan.")