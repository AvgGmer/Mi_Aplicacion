import os
import json
import time
import imaplib
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from dotenv import load_dotenv
from threading import Lock
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import pytz
import io
import sys
import signal
from flask_socketio import SocketIO
import logging

# Manejo de errores en la salida estándar
class WSGIErrorHandler:
    def __init__(self, stream):
        self._stream = stream

    def write(self, data):
        try:
            return self._stream.write(data)
        except BrokenPipeError:
            return None
        except Exception:
            return None

    def flush(self):
        try:
            return self._stream.flush()
        except BrokenPipeError:
            return None
        except Exception:
            return None

# Configuración de logging
logger = logging.getLogger("MiAplicacion")
logger.setLevel(logging.DEBUG)

# Formato de logging
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# Manejo de logging a consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(formatter)

# Agregar manejador al logger
logger.addHandler(console_handler)

# Configurar manejo de errores para stdout y stderr
sys.stdout = WSGIErrorHandler(io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8"))
sys.stderr = WSGIErrorHandler(io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8"))

logging.basicConfig(
    level=logging.INFO,  # Cambia a ERROR o WARNING según tu necesidad
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

if hasattr(signal, "SIGPIPE"):
    def handle_broken_pipe_error(*args):
        """Ignorar silenciosamente el error Broken Pipe."""
        pass

    signal.signal(signal.SIGPIPE, handle_broken_pipe_error)


# Configuración Básica
sys.path.insert(0, "libs")
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Aplicar el manejador de errores
sys.stdout = WSGIErrorHandler(sys.stdout)
sys.stderr = WSGIErrorHandler(sys.stderr)

# Configurar atributos de cookies de sesión
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2)

)

# Inicializar SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# Configuración global
LOCKOUT_DURATION = timedelta(hours=3)
MAX_ATTEMPTS = 4
SESSION_TIMEOUT = timedelta(hours=2)
FINGERPRINTS_FILE = "device_attempts.json"

# Variables Globales
USER_PASSWORDS = {}
session_lock = Lock()
fingerprint_modificado = False
active_sessions = {}

# Asegurarse de que la clave secreta esté definida
if not app.secret_key:
    try:
        print("Error: SECRET_KEY no se encuentra definida.")
    except BrokenPipeError:
        pass
    exit(1)

# Inyectar la función time
@app.context_processor
def inject_time():
    return dict(time=lambda: int(time.time()))

IMAP_SERVER = os.getenv("IMAP_SERVER")
EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
TZ = pytz.timezone("America/Bogota")

# Configuración de la Aplicación
PASSWORDS_FILE = "user_passwords.json"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

@app.route('/favicon.ico')
def favicon():
    return "", 204

def handle_broken_pipe(signum, frame):
    sys.stderr.write('Broken pipe, continuando...\n')
    sys.stderr.flush()
    return

if hasattr(signal, 'SIGPIPE'):
    signal.signal(signal.SIGPIPE, handle_broken_pipe)

def cargar_fingerprints():
    """Carga los registros de fingerprints desde un archivo JSON."""
    try:
        with open(FINGERPRINTS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            # Convertir tiempos de bloqueo a objetos datetime
            for fingerprint, details in list(data.items()):
                try:
                    if "bloqueo" in details and details["bloqueo"]:
                        details["bloqueo"] = datetime.fromisoformat(details["bloqueo"])
                except Exception:
                    del data[fingerprint]  # Eliminar registros inválidos
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Archivo de fingerprints no encontrado o corrupto. Creando uno nuevo.")
        return {}
    except Exception as e:
        print(f"Error al cargar fingerprints: {e}")
        return {}

def guardar_fingerprints():
    """Guarda los registros de fingerprints en un archivo JSON."""
    try:
        with open(FINGERPRINTS_FILE, "w", encoding="utf-8") as file:
            json.dump(device_attempts, file, indent=4, ensure_ascii=False, default=str)
    except Exception as e:
        print(f"Error al guardar fingerprints: {e}")

# Inicializar device_attempts antes de cualquier operación
device_attempts = cargar_fingerprints()

# Guardar fingerprints después de la inicialización
guardar_fingerprints()

def generar_fingerprint(request):
    """Genera un identificador único basado en User-Agent y una cookie."""
    user_agent = request.headers.get("User-Agent", "unknown_agent")
    unique_id = request.cookies.get("unique_id", "unknown_id")
    fingerprint = f"{user_agent}_{unique_id}"
    print(f"Fingerprint generado por el servidor: {fingerprint}")
    return fingerprint

def verificar_intentos(fingerprint):
    """Verifica si un dispositivo está bloqueado o excedió los intentos fallidos."""
    ahora = datetime.now(TZ)
    if fingerprint in device_attempts:
        bloqueo = device_attempts[fingerprint].get("bloqueo")
        if bloqueo and ahora < bloqueo:
            return True, bloqueo  # Bloqueado
        elif bloqueo and ahora >= bloqueo:
            # Desbloquear después de la duración
            device_attempts[fingerprint] = {"intentos": 0, "bloqueo": None}
            guardar_fingerprints()
    return False, None  # No está bloqueado

def registrar_intento_fallido(fingerprint):
    global fingerprint_modificado
    ahora = datetime.now(TZ)
    if fingerprint not in device_attempts:
        device_attempts[fingerprint] = {"intentos": 0, "bloqueo": None}
        fingerprint_modificado = True
    device_attempts[fingerprint]["intentos"] += 1
    fingerprint_modificado = True

    if device_attempts[fingerprint]["intentos"] >= MAX_ATTEMPTS:
        device_attempts[fingerprint]["bloqueo"] = ahora + LOCKOUT_DURATION
        fingerprint_modificado = True
        guardar_fingerprints_si_modificado()  # Guardar después de modificar
        return True  # Bloqueado

    guardar_fingerprints_si_modificado()  # Guardar después de modificar
    return False  # No bloqueado

def limpiar_fingerprints_inactivos():
    global fingerprint_modificado
    ahora = datetime.now(TZ)
    eliminar = []
    for fingerprint, data in device_attempts.items():
        bloqueo = data.get("bloqueo")
        if bloqueo and ahora > bloqueo + timedelta(hours=24):
            eliminar.append(fingerprint)
    for fingerprint in eliminar:
        del device_attempts[fingerprint]
        fingerprint_modificado = True
    guardar_fingerprints_si_modificado()  # Guardar después de limpiar

def guardar_fingerprints_si_modificado():
    """Guarda fingerprints si ha habido cambios."""
    global fingerprint_modificado
    if fingerprint_modificado:
        guardar_fingerprints()
        fingerprint_modificado = False

def verificar_expiracion_sesion():
    """Verifica si la sesión ha expirado y la cierra si es necesario."""
    if "login_time" in session:
        tiempo_actual = datetime.now(TZ)
        login_time = session["login_time"]
        if isinstance(login_time, str):  # Convertir desde string si es necesario
            login_time = datetime.fromisoformat(login_time)
        tiempo_transcurrido = tiempo_actual - login_time
        if tiempo_transcurrido > SESSION_TIMEOUT:
            session.clear()
            flash("Su sesión ha expirado. Por favor, inicie sesión nuevamente.", "info")
            return redirect(url_for("index"))
    return None

# Funciones de Gestión de Contraseñas
def cargar_contraseñas():
    """Carga las contraseñas desde un archivo JSON, asegurando que los campos de expiración sean objetos datetime."""
    try:
        with open(PASSWORDS_FILE, "r", encoding="utf-8") as file:
            contraseñas_cargadas = json.load(file)
            for password, data in contraseñas_cargadas.items():
                if "expiracion" in data and data["expiracion"]:
                    data["expiracion"] = datetime.fromisoformat(data["expiracion"])
            return contraseñas_cargadas
    except FileNotFoundError:
        return {}
    except Exception as e:
        try:
            print(f"Error al cargar contraseñas: {e}")
        except BrokenPipeError:
            pass

def guardar_contraseñas():
    """Guarda las contraseñas en un archivo JSON, asegurando que los objetos datetime sean serializables."""
    try:
        with open(PASSWORDS_FILE, "w", encoding="utf-8") as file:
            contraseñas_serializables = {
                password: {
                    "expiracion": (
                        data["expiracion"].isoformat() if isinstance(data["expiracion"], datetime) else data["expiracion"]
                    ),
                    "estado": data.get("estado", "activa"),
                    "rol": data.get("rol", "estándar")
                }
                for password, data in USER_PASSWORDS.items()
            }
            json.dump(contraseñas_serializables, file, indent=4, ensure_ascii=False)
    except Exception as e:
        try:
            print(f"Error al guardar contraseñas: {e}")
        except BrokenPipeError:
            pass

USER_PASSWORDS = cargar_contraseñas()

def crear_contraseña(password, duracion=None):
    try:
        expiracion = None
        if duracion:
            expiracion = datetime.now(TZ) + timedelta(**duracion)
        USER_PASSWORDS[password] = {"expiracion": expiracion, "estado": "activa"}
        guardar_contraseñas()
    except Exception as e:
        try:
            print(f"Error al crear contraseña: {e}")
        except BrokenPipeError:
            pass

def eliminar_contraseña(password):
    if password in USER_PASSWORDS:
        del USER_PASSWORDS[password]
        guardar_contraseñas()

# Funciones de Correo
def conectar_y_listar_correos(correo_cliente):
    try:
        conexion = imaplib.IMAP4_SSL(IMAP_SERVER)
        conexion.login(EMAIL, PASSWORD)
        conexion.select("inbox")
        _, mensajes = conexion.search(None, f'(TO "{correo_cliente}")')
        ids = mensajes[0].split()[-50:]  # Obtener solo los últimos 50 correos
        correos = []
        tiempo_actual = datetime.now(TZ)
        limite_tiempo = tiempo_actual - timedelta(minutes=20)  # Últimos 20 minutos

        for correo_id in reversed(ids):  # Procesar del más reciente al más antiguo
            _, datos = conexion.fetch(correo_id, "(RFC822)")
            for respuesta in datos:
                if isinstance(respuesta, tuple):
                    mensaje = email.message_from_bytes(respuesta[1])
                    asunto, encoding = decode_header(mensaje["Subject"])[0]
                    if isinstance(asunto, bytes):
                        asunto = asunto.decode(encoding if encoding else "utf-8", errors="ignore")
                    remitente = mensaje.get("From")
                    fecha = parsedate_to_datetime(mensaje["Date"]).astimezone(TZ)

                    # Filtrar solo correos dentro del rango de tiempo
                    if fecha >= limite_tiempo:
                        contenido = None
                        if mensaje.is_multipart():
                            for parte in mensaje.walk():
                                content_type = parte.get_content_type()
                                if content_type == "text/html":
                                    contenido = parte.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    break
                                elif content_type == "text/plain" and not contenido:
                                    contenido = parte.get_payload(decode=True).decode("utf-8", errors="ignore")
                        else:
                            contenido = mensaje.get_payload(decode=True).decode("utf-8", errors="ignore")

                        correos.append({
                            "asunto": asunto,
                            "remitente": remitente,
                            "fecha": fecha.strftime("%d/%m/%Y %I:%M:%S %p"),
                            "contenido": contenido,
                        })

        conexion.logout()
        return correos  # Los correos más recientes ya están primero
    except Exception as e:
        try:
            print(f"Error al listar correos: {e}")
        except BrokenPipeError:
            pass

limpiar_fingerprints_inactivos()
guardar_fingerprints()

# Rutas
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        session.clear()
        password = request.form.get("password")
        fingerprint = generar_fingerprint(request)
        limpiar_fingerprints_inactivos()
        guardar_fingerprints_si_modificado()

        bloqueado, desbloqueo = verificar_intentos(fingerprint)
        if bloqueado:
            flash(f"Dispositivo bloqueado hasta {desbloqueo.strftime('%d/%m/%Y %I:%M:%S %p')}.", "danger")
            return render_template("index.html")

        if password in USER_PASSWORDS:
            flash("Inicio de sesión exitoso.", "success")
            session["authenticated"] = True
            session["login_time"] = datetime.now(TZ).isoformat()
            device_attempts[fingerprint] = {"intentos": 0, "bloqueo": None}
            fingerprint_modificado = True
            active_sessions[fingerprint] = {
                "password": password,
                "login_time": datetime.now(TZ),
                "ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent"),
            }
            guardar_fingerprints_si_modificado()
            return redirect(url_for("correo_app"))
        else:
            if registrar_intento_fallido(fingerprint):
                flash(f"Demasiados intentos fallidos. Dispositivo bloqueado por {LOCKOUT_DURATION.total_seconds() / 3600:.1f} horas.", "danger")
            else:
                intentos_restantes = MAX_ATTEMPTS - device_attempts[fingerprint]["intentos"]
                flash(f"Credenciales incorrectas. Le quedan {intentos_restantes} intentos antes del bloqueo.", "warning")
            guardar_fingerprints_si_modificado()
            return render_template("index.html")

    # Manejar el caso por defecto (GET u otros)
    return render_template("index.html")

limpiar_fingerprints_inactivos()
guardar_fingerprints()

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Ruta para que los administradores inicien sesión."""
    if request.method == "POST":
        usuario = request.form.get("username")
        contraseña = request.form.get("password")
        fingerprint = generar_fingerprint(request)
        bloqueado, desbloqueo = verificar_intentos(fingerprint)
        if bloqueado:
            flash(f"Dispositivo bloqueado hasta {desbloqueo.strftime('%d/%m/%Y %I:%M:%S %p')}.", "danger")
            return render_template("admin_login.html")

        if usuario == ADMIN_USER and contraseña == ADMIN_PASSWORD:
            session["authenticated"] = True
            session["admin_authenticated"] = True
            session["login_time"] = datetime.now(TZ).isoformat()
            device_attempts[fingerprint] = {"intentos": 0, "bloqueo": None}
            active_sessions[fingerprint] = {
                "password": "admin",
                "login_time": datetime.now(TZ),
                "ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent"),
            }
            guardar_fingerprints()
            flash("Inicio de sesión como administrador exitoso.", "success")
            return redirect(url_for("admin_panel"))
        else:
            if registrar_intento_fallido(fingerprint):
                flash(
                    f"Demasiados intentos fallidos. Dispositivo bloqueado por {LOCKOUT_DURATION.total_seconds() / 3600:.1f} horas.",
                    "danger")
            else:
                flash("Credenciales incorrectas.", "danger")
            return render_template("admin_login.html")

    # Siempre renderizar la plantilla de inicio de sesión si no hay redirección
    return render_template("admin_login.html")


@app.route("/admin/panel", methods=["GET", "POST"])
def admin_panel():
    if request.method == "POST":
        accion = request.form.get("action")

        # Modificar la acción de cerrar sesión
        if accion == "cerrar_sesion":
            fingerprint = request.form.get("fingerprint")
            if fingerprint in active_sessions:
                # Emitir evento de socket.io
                socketio.emit("forzar_cierre_sesion", {"fingerprint": fingerprint}, namespace="/")
                # Eliminar la sesión de active_sessions
                active_sessions.pop(fingerprint, None)
                flash(f"Sesión del dispositivo {fingerprint} cerrada exitosamente.", "success")
            else:
                flash("Fingerprint no encontrado en sesiones activas.", "danger")

        # Modificar la acción de bloquear dispositivo
        elif accion == "bloquear_dispositivo":
            fingerprint = request.form.get("fingerprint")
            if fingerprint in device_attempts:
                ahora = datetime.now(TZ)
                device_attempts[fingerprint]["bloqueo"] = None
                device_attempts[fingerprint]["intentos"] = 0
                fingerprint_modificado = True
                guardar_fingerprints_si_modificado()

                # Emitir evento de socket.io
                socketio.emit("forzar_cierre_sesion", {"fingerprint": fingerprint}, namespace="/")
                # Eliminar la sesión de active_sessions
                active_sessions.pop(fingerprint, None)

                flash(f"Dispositivo {fingerprint} bloqueado exitosamente.", "success")
            else:
                flash("Fingerprint no encontrado.", "danger")

        # Procesar otras acciones, como creación de contraseñas
        password = request.form.get("password")
        duration_type = request.form.get("duration")
        quantity = request.form.get("quantity")

        if accion == "crear" and password and duration_type:
            try:
                now = datetime.now(TZ)
                if duration_type == "hours":
                    expiracion = now + timedelta(hours=1)
                elif duration_type == "days":
                    expiracion = now + timedelta(days=1)
                elif duration_type == "months":
                    expiracion = now + relativedelta(months=1)
                elif duration_type == "years":
                    expiracion = now + relativedelta(years=1)
                else:
                    flash("Tipo de duración no válido.", "danger")
                    return redirect(url_for("admin_panel"))

                if password in USER_PASSWORDS:
                    flash("La contraseña ya existe. Use un nombre diferente.", "danger")
                else:
                    USER_PASSWORDS[password] = {
                        "expiracion": expiracion,
                        "estado": "activa",
                        "rol": "estándar"
                    }
                    guardar_contraseñas()
                    flash(f"Contraseña {password} creada exitosamente con duración de {duration_type}.", "success")
            except Exception as e:
                flash(f"Error al crear la contraseña: {e}", "danger")

        # Procesar activación/desactivación/eliminación de contraseñas
        elif accion in ["activar", "desactivar", "eliminar"] and password:
            if password not in USER_PASSWORDS:
                flash("La contraseña especificada no existe.", "danger")
            else:
                if accion == "activar":
                    USER_PASSWORDS[password]["estado"] = "activa"
                    flash(f"Contraseña {password} activada.", "success")
                elif accion == "desactivar":
                    USER_PASSWORDS[password]["estado"] = "inactiva"
                    flash(f"Contraseña {password} desactivada.", "info")
                elif accion == "eliminar":
                    del USER_PASSWORDS[password]
                    flash(f"Contraseña {password} eliminada.", "danger")
                guardar_contraseñas()

        # Actualizar credenciales administrativas
        elif accion == "actualizar_credenciales":
            nuevo_usuario = request.form.get("username")
            nueva_contraseña = request.form.get("password")
            if nuevo_usuario and nueva_contraseña:
                os.environ["ADMIN_USER"] = nuevo_usuario
                os.environ["ADMIN_PASSWORD"] = nueva_contraseña
                flash("Credenciales administrativas actualizadas exitosamente.", "success")
            else:
                flash("Debe completar todos los campos para actualizar las credenciales.", "danger")

    # Obtener lista de dispositivos bloqueados
    dispositivos_bloqueados = [
        {"fingerprint": fp, "bloqueo": data["bloqueo"].strftime("%d/%m/%Y %I:%M:%S %p")}
        for fp, data in device_attempts.items()
        if data["bloqueo"]
    ]

    # Obtener contraseñas existentes
    contraseñas = [
        {
            "password": pw,
            "expiracion": data["expiracion"].strftime("%d/%m/%Y %I:%M:%S %p") if data["expiracion"] else "Sin expiración",
            "estado": data["estado"],
            "rol": data.get("rol", "estándar"),
        }
        for pw, data in USER_PASSWORDS.items()
    ]

    return render_template(
        "admin_panel.html",
        contraseñas=contraseñas,
        dispositivos_bloqueados=dispositivos_bloqueados,
        admin_access=True,
    )
guardar_fingerprints()


@app.route("/api/check_session_status", methods=["POST"])
def check_session_status():
    data = request.get_json()
    fingerprint = data.get("fingerprint")

    if fingerprint in device_attempts and device_attempts[fingerprint].get("bloqueo"):
        return jsonify({"status": "blocked"})
    if fingerprint not in active_sessions:
        return jsonify({"status": "closed"})
    return jsonify({"status": "active"})

@app.route("/api/dispositivos_bloqueados", methods=["GET"])
def obtener_dispositivos_bloqueados():
    """Devuelve los dispositivos bloqueados en formato JSON."""
    dispositivos_bloqueados = [
        {"fingerprint": fp, "bloqueo": data["bloqueo"].strftime("%d/%m/%Y %I:%M:%S %p")}
        for fp, data in device_attempts.items()
        if data["bloqueo"]
    ]
    return {"dispositivos_bloqueados": dispositivos_bloqueados}

@app.route("/api/sesiones_activas", methods=["GET"])
def obtener_sesiones_activas():
    """Devuelve las sesiones activas en formato JSON."""
    return {
        "sesiones_activas": [
            {
                "fingerprint": fp,
                "password": data["password"],
                "login_time": data["login_time"].strftime("%d/%m/%Y %I:%M:%S %p"),
                "ip": data["ip"],
                "user_agent": data["user_agent"],
            }
            for fp, data in active_sessions.items()
        ]
    }

@app.route("/admin/update-credentials", methods=["POST"])
def update_credentials():
    """Actualiza las credenciales del administrador."""
    if not session.get("admin_authenticated"):
        flash("Debe iniciar sesión como administrador para acceder.", "danger")
        return redirect(url_for("admin_login"))

    nuevo_usuario = request.form.get("username")
    nueva_contraseña = request.form.get("password")

    if not nuevo_usuario or not nueva_contraseña:
        flash("Todos los campos son obligatorios.", "danger")
        return redirect(url_for("admin_panel"))

    os.environ["ADMIN_USER"] = nuevo_usuario
    os.environ["ADMIN_PASSWORD"] = nueva_contraseña
    flash("Credenciales administrativas actualizadas exitosamente.", "success")
    return redirect(url_for("admin_panel"))

@app.route("/app", methods=["GET", "POST"])
def correo_app():
    verificacion = verificar_expiracion_sesion()
    if verificacion:
        return verificacion

    if not session.get("authenticated") and not session.get("admin_authenticated"):
        flash("Debe iniciar sesión.", "danger")
        return redirect(url_for("index"))

    correos = []
    is_admin = session.get("admin_authenticated", False)  # Verificar si es administrador

    if request.method == "POST":
        correo_cliente = request.form.get("correo_cliente")
        correos = conectar_y_listar_correos(correo_cliente)

    return render_template("correo_app.html", correos=correos, is_admin=is_admin)

@app.route("/logout")
def logout():
    if session.get("admin_authenticated"):
        session.pop("admin_authenticated", None)
        flash("Sesión de administrador cerrada.", "info")
    else:
        session.clear()
        flash("Sesión cerrada.", "info")
    return redirect(url_for("index"))

@app.errorhandler(BrokenPipeError)
def handle_broken_pipe_error(e):
    logger.warning(f"BrokenPipeError ignorado: {e}")
    return "", 204

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Error no manejado: {str(e)}")
    return "Ha ocurrido un error interno", 500

application = app

if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        socketio.run(
            app,
            host="0.0.0.0",
            port=port,
            debug=False,  # Importante: debug=False en producción
            log_output=True
        )
    except Exception as e:
        logger.error(f"Error al iniciar la aplicación: {e}")
        sys.exit(1)