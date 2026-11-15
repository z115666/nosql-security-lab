"""
API NoSQL ENDURECIDA.

Contramedidas aplicadas (cada una referenciada en el informe):
  C1  Validación estricta de entrada con Pydantic (extra="forbid", tipos estrictos,
      patrones y longitudes) + filtro global que rechaza claves "$" y "." (NoSQLi).
  C2  Login sin la contraseña en la consulta: búsqueda por username y bcrypt.checkpw.
  C3  Autenticación con JWT de vida corta y autorización por rol (RBAC de aplicación):
      cada cliente solo ve sus pedidos; solo "admin" borra.
  C4  Búsqueda en Elasticsearch con multi_match (sin sintaxis Lucene), paginada,
      con tamaño máximo, _source limitado y un usuario ES de solo lectura.
  C5  Conexiones a MongoDB (SCRAM + TLS, usuario readWrite solo en "tienda") y a
      Elasticsearch (Basic auth + TLS verificando la CA del laboratorio).
  C6  Rate limiting (slowapi) en login y búsqueda.
  C7  Registro de seguridad en JSON (stdout + fichero) y alertas: fuerza bruta en
      login y picos de búsqueda.
  C8  Errores genéricos (sin filtrar trazas ni datos de entrada), cabeceras de
      seguridad y documentación interactiva desactivada por defecto.
"""
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt
import requests
from bson import ObjectId
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ------------------------------------------------------------------ config
def _env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"Falta la variable de entorno obligatoria {name}")
    return val or ""


JWT_SECRET = _env("JWT_SECRET", required=True)
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET debe tener al menos 32 caracteres")
JWT_TTL_MIN = int(_env("JWT_TTL_MIN", "15"))

MONGO_HOST = _env("MONGO_HOST", "mongo")
MONGO_DB = _env("MONGO_DATABASE", "tienda")
MONGO_USER = _env("MONGO_APP_USER")
MONGO_PASS = _env("MONGO_APP_PASSWORD")
TLS_CA = _env("TLS_CA_FILE", "/certs/ca.crt")
MONGO_TLS = _env("MONGO_TLS", "true").lower() == "true"

ES_URL = _env("ELASTIC_URL", "https://elasticsearch:9200")
ES_USER = _env("ES_APP_USER")
ES_PASS = _env("ES_APP_PASSWORD")
ES_VERIFY: Any = TLS_CA if ES_URL.startswith("https") else True

ALERT_LOGIN_FAILS = int(_env("ALERT_LOGIN_FAILS", "5"))      # fallos / 60 s / IP
ALERT_SEARCH_SPIKE = int(_env("ALERT_SEARCH_SPIKE", "20"))   # búsquedas / 60 s / IP
LOG_FILE = _env("SECURITY_LOG_FILE", "/app/logs/security.log")

# ----------------------------------------------------------------- logging
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        base.update(getattr(record, "extra_fields", {}))
        return json.dumps(base, ensure_ascii=False)


seclog = logging.getLogger("security")
seclog.setLevel(logging.INFO)
seclog.propagate = False
_sh = logging.StreamHandler()
_sh.setFormatter(JsonFormatter())
seclog.addHandler(_sh)
try:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    _fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    _fh.setFormatter(JsonFormatter())
    seclog.addHandler(_fh)
except OSError:
    seclog.warning("log_file_unavailable", extra={"extra_fields": {"path": LOG_FILE}})


def audit(event: str, level: int = logging.INFO, **fields: Any) -> None:
    seclog.log(level, event, extra={"extra_fields": fields})


# ------------------------------------------------------------------ alertas
_windows: dict[str, deque] = defaultdict(deque)


def _hit(kind: str, key: str, threshold: int, window_s: int = 60) -> None:
    now = time.time()
    dq = _windows[f"{kind}:{key}"]
    dq.append(now)
    while dq and now - dq[0] > window_s:
        dq.popleft()
    if len(dq) == threshold:  # se avisa una vez al cruzar el umbral
        audit("ALERTA_" + kind.upper(), logging.WARNING, ip=key,
              eventos=len(dq), ventana_s=window_s)


# ---------------------------------------------------------------- recursos
_db = None


def get_db():
    """Conexión perezosa (permite inyectar una BD simulada en los tests)."""
    global _db
    if _db is None:
        client = MongoClient(
            MONGO_HOST, 27017,
            username=MONGO_USER, password=MONGO_PASS, authSource=MONGO_DB,
            tls=MONGO_TLS, tlsCAFile=TLS_CA if MONGO_TLS else None,
            serverSelectionTimeoutMS=5000,
        )
        _db = client[MONGO_DB]
    return _db


# ---------------------------------------------------------------- app base
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="API NoSQL (endurecida)",
    docs_url="/docs" if _env("ENABLE_DOCS", "false") == "true" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _env("ENABLE_DOCS", "false") == "true" else None,
)
app.state.limiter = limiter


def _ip(request: Request) -> str:
    return request.client.host if request.client else "desconocida"


@app.exception_handler(RateLimitExceeded)
async def on_rate_limit(request: Request, exc: RateLimitExceeded):
    audit("rate_limited", logging.WARNING, ip=_ip(request), path=request.url.path)
    return JSONResponse(status_code=429, content={"detail": "Demasiadas peticiones"})


@app.exception_handler(RequestValidationError)
async def on_validation(request: Request, exc: RequestValidationError):
    errores = [{"campo": ".".join(str(x) for x in e["loc"]), "motivo": e["msg"]}
               for e in exc.errors()]
    audit("validation_rejected", logging.WARNING, ip=_ip(request),
          path=request.url.path, campos=[e["campo"] for e in errores])
    # No se devuelve el valor recibido (evita reflejar payloads)
    return JSONResponse(status_code=422, content={"detail": "Entrada no válida",
                                                  "errores": errores})


def _has_operator(obj: Any) -> bool:
    if isinstance(obj, dict):
        return any(str(k).startswith("$") or "." in str(k) or _has_operator(v)
                   for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_operator(v) for v in obj)
    return False


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # C1 (defensa en profundidad): bloquear operadores de MongoDB en cuerpos JSON
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if body:
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            if parsed is not None and _has_operator(parsed):
                audit("nosqli_blocked", logging.WARNING, ip=_ip(request),
                      path=request.url.path)
                return JSONResponse(status_code=422, content={
                    "detail": "Entrada no válida: operadores no permitidos"})
    response = await call_next(request)
    # C8: cabeceras de seguridad
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# ------------------------------------------------------------------ modelos
USERNAME_RE = r"^[A-Za-z0-9_.-]{3,32}$"
TEXTO_RE = r"^[0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ \"'.,()-]{1,80}$"
BUSQUEDA_RE = r"^[0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ -]{2,50}$"
OID_RE = r"^[a-f0-9]{24}$"


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_RE)
    password: str = Field(min_length=6, max_length=72)

    @field_validator("password")
    @classmethod
    def max_72_bytes(cls, v: str) -> str:
        # bcrypt solo procesa 72 bytes; bcrypt>=5 lanza error si se superan
        if len(v.encode("utf-8")) > 72:
            raise ValueError("contraseña demasiado larga")
        return v


class PedidoIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    producto: str = Field(min_length=1, max_length=80, pattern=TEXTO_RE)
    cantidad: int = Field(ge=1, le=1000)


# --------------------------------------------------------------- seguridad
bearer = HTTPBearer(auto_error=False)


def crear_token(username: str, rol: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": username, "rol": rol, "iat": now,
                       "exp": now + timedelta(minutes=JWT_TTL_MIN)},
                      JWT_SECRET, algorithm="HS256")


def usuario_actual(request: Request,
                   cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
    if cred is None:
        audit("auth_missing", logging.WARNING, ip=_ip(request), path=request.url.path)
        raise HTTPException(401, "Autenticación requerida",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(cred.credentials, JWT_SECRET, algorithms=["HS256"],
                            options={"require": ["exp", "sub", "rol"]})
    except jwt.PyJWTError:
        audit("auth_invalid_token", logging.WARNING, ip=_ip(request), path=request.url.path)
        raise HTTPException(401, "Token no válido",
                            headers={"WWW-Authenticate": "Bearer"})
    return {"username": claims["sub"], "rol": claims["rol"]}


def solo_admin(request: Request, user: dict = Depends(usuario_actual)) -> dict:
    if user["rol"] != "admin":
        audit("forbidden", logging.WARNING, ip=_ip(request), path=request.url.path,
              usuario=user["username"], rol=user["rol"])
        raise HTTPException(403, "Permisos insuficientes")
    return user


def _out(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


def _db_or_503():
    try:
        return get_db()
    except PyMongoError:
        audit("db_unavailable", logging.ERROR)
        raise HTTPException(503, "Servicio no disponible")


# ---------------------------------------------------------------- endpoints
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login_mongo")
@limiter.limit("10/minute")
def login(request: Request, cred: Login):
    ip = _ip(request)
    try:
        user = _db_or_503().usuarios.find_one({"username": cred.username},
                                              {"_id": 0, "username": 1,
                                               "password_hash": 1, "rol": 1})
    except PyMongoError:
        audit("db_error", logging.ERROR, ip=ip)
        raise HTTPException(503, "Servicio no disponible")
    ok = bool(user) and bcrypt.checkpw(cred.password.encode(),
                                       user["password_hash"].encode())
    if not ok:
        audit("login_fail", logging.WARNING, ip=ip, usuario=cred.username)
        _hit("fuerza_bruta_login", ip, ALERT_LOGIN_FAILS)
        raise HTTPException(401, "Credenciales no válidas")
    audit("login_ok", ip=ip, usuario=user["username"], rol=user["rol"])
    return {"access_token": crear_token(user["username"], user["rol"]),
            "token_type": "bearer", "expires_in": JWT_TTL_MIN * 60}


@app.get("/pedidos")
def listar_pedidos(user: dict = Depends(usuario_actual),
                   page: int = Query(1, ge=1, le=1000),
                   size: int = Query(10, ge=1, le=50)):
    filtro = {} if user["rol"] == "admin" else {"usuario": user["username"]}
    cur = (_db_or_503().pedidos.find(filtro).sort("_id", 1)
           .skip((page - 1) * size).limit(size))
    return {"page": page, "size": size, "items": [_out(p) for p in cur]}


@app.post("/pedidos", status_code=201)
def crear_pedido(p: PedidoIn, request: Request, user: dict = Depends(usuario_actual)):
    res = _db_or_503().pedidos.insert_one({"usuario": user["username"], **p.model_dump()})
    audit("pedido_creado", ip=_ip(request), usuario=user["username"], id=str(res.inserted_id))
    return {"id": str(res.inserted_id)}


@app.put("/pedidos/{pid}")
def actualizar_pedido(p: PedidoIn, request: Request,
                      pid: str = Path(pattern=OID_RE),
                      user: dict = Depends(usuario_actual)):
    filtro: dict = {"_id": ObjectId(pid)}
    if user["rol"] != "admin":
        filtro["usuario"] = user["username"]  # solo sus propios pedidos
    res = _db_or_503().pedidos.update_one(filtro, {"$set": p.model_dump()})
    if not res.matched_count:
        raise HTTPException(404, "No existe")
    audit("pedido_actualizado", ip=_ip(request), usuario=user["username"], id=pid)
    return {"actualizado": pid}


@app.delete("/pedidos/{pid}")
def borrar_pedido(request: Request, pid: str = Path(pattern=OID_RE),
                  user: dict = Depends(solo_admin)):
    res = _db_or_503().pedidos.delete_one({"_id": ObjectId(pid)})
    if not res.deleted_count:
        raise HTTPException(404, "No existe")
    audit("pedido_borrado", ip=_ip(request), usuario=user["username"], id=pid)
    return {"borrado": pid}


@app.get("/articulos")
@limiter.limit("30/minute")
def buscar_articulos(request: Request,
                     q: str = Query(min_length=2, max_length=50, pattern=BUSQUEDA_RE),
                     page: int = Query(1, ge=1, le=100),
                     size: int = Query(10, ge=1, le=20)):
    ip = _ip(request)
    _hit("pico_busquedas", ip, ALERT_SEARCH_SPIKE)
    body = {
        "query": {"multi_match": {"query": q, "fields": ["nombre^2", "descripcion"],
                                  "operator": "and"}},
        "from": (page - 1) * size, "size": size,
        "_source": ["nombre", "descripcion", "categoria", "precio"],
    }
    try:
        r = requests.post(f"{ES_URL}/articulos/_search", json=body,
                          auth=(ES_USER, ES_PASS), verify=ES_VERIFY, timeout=5)
        r.raise_for_status()
        hits = r.json()["hits"]
    except (requests.RequestException, KeyError, ValueError):
        audit("search_backend_error", logging.ERROR, ip=ip)
        raise HTTPException(502, "Búsqueda no disponible")
    audit("search", ip=ip, q_len=len(q), resultados=hits["total"]["value"])
    return {"page": page, "size": size, "total": hits["total"]["value"],
            "items": [h["_source"] for h in hits["hits"]]}
