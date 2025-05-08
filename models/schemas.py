from pydantic import BaseModel
from typing import List, Optional

class OrquestarRequest(BaseModel):
    servicio_destino: str
    parametros_adicionales: Optional[dict]

class RegistrarServicioRequest(BaseModel):
    nombre: str
    descripcion: str
    endpoints: List[str]

class ActualizarReglasRequest(BaseModel):
    reglas: dict

class AutenticarUsuarioRequest(BaseModel):
    nombre_usuario: str
    contrasena: str

class AutorizarAccesoRequest(BaseModel):
    recursos: List[str]
    rol_usuario: str