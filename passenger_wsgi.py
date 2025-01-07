import sys
import os

# Añadir la ruta del entorno virtual
sys.path.insert(0, '/home/newlunaq/public_html/mi_aplicacion/venv/lib/python3.6/site-packages')

# Añadir la ruta del proyecto
sys.path.insert(0, '/home/newlunaq/public_html/mi_aplicacion')

# Cargar las variables de entorno
from dotenv import load_dotenv
load_dotenv(os.path.join('/home/newlunaq/public_html/mi_aplicacion', '.env'))

# Importar la aplicación Flask
from Mail import app as application