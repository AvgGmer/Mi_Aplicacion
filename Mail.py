import sys
sys.path.insert(0, "libs")  # Configura el uso de dependencias locales desde la carpeta 'libs'

from flask import Flask, render_template, request
from markupsafe import Markup  # Importación corregida
import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
import pytz  # Librería para manejar zonas horarias
from decouple import config  # Importar decouple para usar variables del archivo .env

# Configuración del correo madre desde el archivo .env
IMAP_SERVER = config("IMAP_SERVER", default="mail.gadafa.com")
EMAIL = config("EMAIL")  # Correo madre
PASSWORD = config("PASSWORD")  # Contraseña del correo madre

# Configuración de la zona horaria
TZ = pytz.utc  # Usamos UTC como estándar

app = Flask(__name__)

def conectar_y_listar_correos(correo_cliente):
    try:
        # Conexión al servidor IMAP
        conexion = imaplib.IMAP4_SSL(IMAP_SERVER)
        conexion.login(EMAIL, PASSWORD)

        # Seleccionar bandeja de entrada
        conexion.select("inbox")

        # Obtener la fecha y hora actuales y el rango de 20 minutos atrás
        ahora = datetime.now(TZ)  # Convertir a zona horaria consciente
        hace_20_minutos = ahora - timedelta(minutes=20)

        # Filtrar correos por el correo del cliente (TO)
        status, mensajes = conexion.search(None, f'(TO "{correo_cliente}")')

        # Verificar si hay resultados
        if status != "OK" or not mensajes[0]:
            return []

        # Lista de IDs de correos que coinciden
        ids = mensajes[0].split()

        # Extraer la información de cada correo
        correos = []
        for correo_id in ids:
            # Obtener los datos del correo
            status, datos = conexion.fetch(correo_id, "(RFC822)")
            for respuesta in datos:
                if isinstance(respuesta, tuple):  # Comprobación de que es una tupla
                    # Decodificar el mensaje del correo
                    mensaje = email.message_from_bytes(respuesta[1])

                    # Decodificar el asunto
                    asunto, encoding = decode_header(mensaje["Subject"])[0]
                    if isinstance(asunto, bytes):
                        asunto = asunto.decode(encoding if encoding else "utf-8")

                    # Obtener el remitente
                    remitente = mensaje.get("From")

                    # Obtener la fecha del correo
                    fecha = mensaje["Date"]
                    fecha_correo = email.utils.parsedate_to_datetime(fecha).astimezone(TZ)  # Convertir a zona horaria consciente

                    # Filtrar correos fuera del rango de tiempo
                    if fecha_correo < hace_20_minutos or fecha_correo > ahora:
                        continue

                    # Obtener el contenido del correo
                    contenido = ""
                    if mensaje.is_multipart():
                        for parte in mensaje.walk():
                            tipo_contenido = parte.get_content_type()
                            if tipo_contenido == "text/html":
                                contenido = parte.get_payload(decode=True).decode("utf-8")
                                break
                    else:
                        if mensaje.get_content_type() == "text/html":
                            contenido = mensaje.get_payload(decode=True).decode("utf-8")

                    # Guardar la información del correo
                    correos.append({
                        "asunto": asunto,
                        "remitente": remitente,
                        "contenido": Markup(contenido.strip()),
                        "fecha": fecha_correo
                    })

        # Cerrar la conexión
        conexion.logout()

        # Ordenar los correos por fecha (más reciente primero)
        correos = sorted(correos, key=lambda x: x["fecha"], reverse=True)

        return correos

    except Exception as e:
        print(f"Error: {e}")
        return []

@app.route("/", methods=["GET", "POST"])
def index():
    correos = None
    correo_cliente = None
    if request.method == "POST":
        correo_cliente = request.form["correo_cliente"]
        correos = conectar_y_listar_correos(correo_cliente)
    return render_template("index.html", correos=correos, correo_cliente=correo_cliente)

if __name__ == "__main__":
    app.run(debug=True)