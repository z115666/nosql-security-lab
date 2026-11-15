"""
API NoSQL VULNERABLE — solo laboratorio.

Basada en el código de apoyo de la actividad. Fallos introducidos a propósito:
  * /login_mongo pasa el JSON del cliente tal cual a find_one -> NoSQL Injection
    con operadores ($ne, $gt, $regex...).
  * Contraseñas guardadas y comparadas en claro.
  * /articulos reenvía "q" a la sintaxis query_string de Lucene sin filtrar,
    sin paginar y devolviendo todos los campos (incluido coste_interno).
  * Sin autenticación ni autorización en el CRUD de pedidos.
  * Conexión a MongoDB y Elasticsearch sin credenciales ni TLS.
"""
import os

import requests
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from pymongo import MongoClient

app = FastAPI(title="API NoSQL (vulnerable)")
mongo = MongoClient(os.getenv("MONGO_HOST", "mongo"), 27017)
db = mongo[os.getenv("MONGO_DATABASE", "tienda")]
ES = f"http://{os.getenv('ELASTIC_HOST', 'elasticsearch')}:9200"


class Login(BaseModel):  # definido pero NO usado: el endpoint lee el JSON crudo
    username: str
    password: str


class Pedido(BaseModel):
    producto: str
    cantidad: int


def _out(doc):
    doc["_id"] = str(doc["_id"])
    return doc


@app.get("/health")
def health():
    return {"status": "ok", "modo": "VULNERABLE"}


@app.post("/login_mongo")
async def login(req: Request):
    data = await req.json()
    # NoSQLi: acepta operadores $ en las credenciales
    user = db.usuarios.find_one(
        {"username": data.get("username"), "password": data.get("password")},
        {"_id": 0},
    )
    if user:
        # Devuelve el perfil del usuario autenticado (como muchas apps reales)
        return {"msg": "ok", "usuario": user["username"], "rol": user["rol"]}
    raise HTTPException(status_code=401, detail="Bad creds")


# ----------------------------- CRUD pedidos -----------------------------
@app.get("/pedidos")
def listar_pedidos():
    return [_out(p) for p in db.pedidos.find()]


@app.post("/pedidos", status_code=201)
def crear_pedido(p: Pedido):
    res = db.pedidos.insert_one({"usuario": "anonimo", **p.model_dump()})
    return {"id": str(res.inserted_id)}


@app.put("/pedidos/{pid}")
def actualizar_pedido(pid: str, p: Pedido):
    res = db.pedidos.update_one({"_id": ObjectId(pid)}, {"$set": p.model_dump()})
    if not res.matched_count:
        raise HTTPException(404, "No existe")
    return {"actualizado": pid}


@app.delete("/pedidos/{pid}")
def borrar_pedido(pid: str):
    res = db.pedidos.delete_one({"_id": ObjectId(pid)})
    if not res.deleted_count:
        raise HTTPException(404, "No existe")
    return {"borrado": pid}


# ----------------------------- Búsqueda ES ------------------------------
@app.get("/articulos")
def art_search(q: str = "*"):
    # Lucene query_string sin filtrar: q=* devuelve todo; q=precio:>0, etc.
    return requests.get(f"{ES}/articulos/_search", params={"q": q}).json()
