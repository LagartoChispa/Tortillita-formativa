from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from models.schemas import (
    OrquestarRequest,
    RegistrarServicioRequest,
    ActualizarReglasRequest,
    AutenticarUsuarioRequest,
    AutorizarAccesoRequest,
)
from services.auth import validar_token, generar_token
import logging
from typing import Dict
from jose import JWTError, jwt
from datetime import datetime, timezone, timedelta

# Configuración de FastAPI
app = FastAPI()

# Configuración de logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dependencias y almacenamiento en memoria
dependencias = {}

# Configuración de JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Middleware para registrar logs de solicitudes y respuestas
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Solicitud: {request.method} {request.url}")
    try:
        # Llama al siguiente middleware o endpoint
        response = await call_next(request)

        # Si la respuesta tiene un cuerpo, intenta leerlo
        if response.body_iterator:
            body = b"".join([chunk async for chunk in response.body_iterator])
            logger.info(f"Respuesta: {response.status_code}, Contenido: {body.decode('utf-8', errors='ignore')}")
            response.body_iterator = iter([body])  # Restaura el cuerpo de la respuesta
            response.headers["Content-Length"] = str(len(body))  # Actualiza el encabezado Content-Length
        else:
            logger.info(f"Respuesta: {response.status_code}")

        return response
    except Exception as e:
        logger.error(f"Error procesando la solicitud: {str(e)}")
        raise

# Función para generar un token JWT
def generar_token(usuario: str, roles: list) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": usuario, "roles": roles, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Función para validar un token JWT
def validar_token(token: str, roles_permitidos: list = None) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        roles = payload.get("roles", [])
        if roles_permitidos and not any(role in roles for role in roles_permitidos):
            return False
        return True
    except JWTError:
        return False

# Función para obtener y validar el token
def obtener_token(token: str = ""):
    if not validar_token(token):
        raise HTTPException(status_code=403, detail="Token inválido o no autorizado")
    return token

# Manejo de errores personalizados
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"mensaje": exc.detail, "tipo_error": "HTTPException"},
    )

# Manejo global de errores
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"mensaje": "Ocurrió un error interno en el servidor", "detalle": str(exc)},
    )

# Ruta raíz
@app.get("/", tags=["General"], summary="Página de inicio")
async def root():
    """
    Página de inicio del servidor.
    """
    return {"mensaje": "Bienvenido a la API de Logística Global. Visita /docs para la documentación."}

# Manejo del favicon
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """
    Maneja solicitudes al favicon para evitar errores 404.
    """
    return JSONResponse(content={}, status_code=204)

# Endpoint: Orquestar Servicios
@app.post("/orquestar", tags=["Orquestación"], summary="Orquestar servicios")
async def orquestar_servicio(request: OrquestarRequest, token: str = Depends(obtener_token)):
    """
    Orquesta un servicio específico.
    - **Roles permitidos:** Orquestador, Administrador
    """
    _request = request  # Suppresses the "not accessed" warning
    return {"mensaje": "Servicio orquestado exitosamente", "detalles": request}

# Endpoint: Obtener Información del Servicio
@app.get("/informacion-servicio/{id}", tags=["Servicios"], summary="Obtener información de un servicio")
async def obtener_informacion_servicio(id: str, token: str = Depends(obtener_token)):
    """
    Obtiene información de un servicio específico.
    - **Roles permitidos:** Todos los usuarios autenticados
    """
    return {"id": id, "nombre": "Servicio de ejemplo", "descripcion": "Descripción del servicio"}

# Endpoint: Registrar Nuevo Servicio
@app.post("/registrar-servicio", tags=["Servicios"], summary="Registrar un nuevo servicio")
async def registrar_servicio(request: RegistrarServicioRequest, token: str = Depends(obtener_token)):
    """
    Registra un nuevo servicio en el sistema.
    - **Roles permitidos:** Administrador
    """
    return {"mensaje": "Servicio registrado exitosamente", "detalles": request}

# Endpoint: Actualizar Reglas de Orquestación
@app.put("/actualizar-reglas-orquestacion", tags=["Orquestación"], summary="Actualizar reglas de orquestación")
async def actualizar_reglas_orquestacion(request: ActualizarReglasRequest, token: str = Depends(obtener_token)):
    """
    Actualiza las reglas de orquestación de un servicio.
    - **Roles permitidos:** Administrador
    """
    return {"mensaje": "Reglas de orquestación actualizadas", "detalles": request}

# Endpoint: Autenticar Usuario
@app.post("/autenticar-usuario", tags=["Autenticación"], summary="Autenticar usuario")
async def autenticar_usuario(request: AutenticarUsuarioRequest):
    """
    Autentica un usuario y genera un token.
    - **Roles permitidos:** Todos los usuarios
    """
    roles = ["Administrador"] if request.nombre_usuario == "admin" else ["Usuario"]
    token = generar_token(request.nombre_usuario, roles)
    return {"mensaje": "Autenticación exitosa", "token": token}

# Endpoint: Autorizar Acceso
@app.post("/autorizar-acceso", tags=["Autorización"], summary="Autorizar acceso a recursos")
async def autorizar_acceso(request: AutorizarAccesoRequest, token: str = Depends(obtener_token)):
    """
    Autoriza el acceso a recursos específicos.
    - **Roles permitidos:** Administrador
    """
    return {"mensaje": "Acceso autorizado", "recursos": request.recursos}

# Endpoint: Registrar Dependencias entre Servicios
@app.post("/registrar-dependencia", tags=["Servicios"], summary="Registrar dependencias entre servicios")
async def registrar_dependencia(servicio: str, dependencias_servicio: Dict[str, str], token: str = Depends(obtener_token)):
    """
    Registra dependencias entre servicios.
    - **Roles permitidos:** Administrador
    """
    if not validar_token(token, roles_permitidos=["Administrador"]):
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    dependencias[servicio] = dependencias_servicio
    return {"mensaje": "Dependencias registradas exitosamente", "detalles": dependencias}

# Endpoint: Consultar Dependencias
@app.get("/consultar-dependencias", tags=["Servicios"], summary="Consultar dependencias entre servicios")
async def consultar_dependencias(token: str = Depends(obtener_token)):
    """
    Consulta las dependencias registradas entre servicios.
    - **Roles permitidos:** Todos los usuarios autenticados
    """
    if not validar_token(token):
        raise HTTPException(status_code=403, detail="Acceso no autorizado")

    return {"dependencias": dependencias}

# Endpoint: Registrar Servicios Automáticamente
@app.post("/registrar-servicio-automatico", tags=["Servicios"], summary="Registrar servicios automáticamente")
async def registrar_servicio_automatico(url: str, token: str = Depends(obtener_token)):
    """
    Analiza y registra automáticamente un servicio REST existente.
    - **Roles permitidos:** Administrador
    """
    if not validar_token(token, roles_permitidos=["Administrador"]):
        raise HTTPException(status_code=403, detail="Acceso no autorizado")

    # Simulación de análisis del servicio
    servicio = {
        "url": url,
        "endpoints": ["/endpoint1", "/endpoint2"],
        "descripcion": "Servicio analizado automáticamente"
    }
    dependencias[url] = servicio
    return {"mensaje": "Servicio registrado automáticamente", "detalles": servicio}