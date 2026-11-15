"""
Pruebas automáticas de la API endurecida (sin Docker): MongoDB simulado con
mongomock y Elasticsearch simulado. Se ejecutan en CI en cada push.
"""
import importlib
import os
import sys

import bcrypt
import mongomock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fastapi-app"))
os.environ.setdefault("JWT_SECRET", "x" * 48)
os.environ.setdefault("SECURITY_LOG_FILE", "/tmp/nosql-lab-tests/security.log")


class FakeESResponse:
    def __init__(self, hits):
        self._hits = hits

    def raise_for_status(self):
        return None

    def json(self):
        return {"hits": {"total": {"value": len(self._hits)},
                         "hits": [{"_source": h} for h in self._hits]}}


@pytest.fixture()
def client(monkeypatch):
    ms = importlib.import_module("app.main_secure")
    ms.limiter.reset()
    ms._windows.clear()
    db = mongomock.MongoClient().tienda
    h = lambda p: bcrypt.hashpw(p.encode(), bcrypt.gensalt(4)).decode()
    db.usuarios.insert_many([
        {"username": "admin", "rol": "admin", "password_hash": h("Adm1n#2026lab")},
        {"username": "alice", "rol": "cliente", "password_hash": h("Alice#2026lab")},
        {"username": "bob", "rol": "cliente", "password_hash": h("Bob#2026lab")},
    ])
    db.pedidos.insert_many([
        {"usuario": "alice", "producto": "Portátil", "cantidad": 1},
        {"usuario": "bob", "producto": "Monitor", "cantidad": 1},
    ])
    ms._db = db
    sent = {}

    def fake_post(url, json=None, **kw):
        sent["body"] = json
        sent["auth"] = kw.get("auth")
        return FakeESResponse([{"nombre": "Portátil 14", "precio": 899.0}])

    monkeypatch.setattr(ms.requests, "post", fake_post)
    c = TestClient(ms.app)
    c.sent = sent
    return c


def login(c, u, p):
    return c.post("/login_mongo", json={"username": u, "password": p})


def auth(c, u, p):
    return {"Authorization": f"Bearer {login(c, u, p).json()['access_token']}"}


@pytest.mark.parametrize("payload", [
    {"username": "alice", "password": {"$ne": "x"}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
    {"username": {"$regex": "^adm"}, "password": {"$gt": ""}},
    {"username": "alice", "password": "Alice#2026lab", "rol": "admin"},
    {"username": "a", "password": "corto"},
])
def test_nosqli_y_entradas_invalidas_devuelven_422(client, payload):
    r = client.post("/login_mongo", json=payload)
    assert r.status_code == 422
    assert "Alice#2026lab" not in r.text  # no se refleja la entrada


def test_operador_como_texto_no_autentica(client):
    assert login(client, "alice", "$ne:xxxx").status_code == 401


def test_login_correcto_e_incorrecto(client):
    assert login(client, "alice", "mala-clave").status_code == 401
    r = login(client, "alice", "Alice#2026lab")
    assert r.status_code == 200 and r.json()["access_token"].startswith("eyJ")


def test_pedidos_requiere_token_y_filtra_por_usuario(client):
    assert client.get("/pedidos").status_code == 401
    r = client.get("/pedidos", headers=auth(client, "alice", "Alice#2026lab"))
    assert r.status_code == 200
    assert {p["usuario"] for p in r.json()["items"]} == {"alice"}


def test_token_alg_none_rechazado(client):
    forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbCI6ImFkbWluIn0."
    r = client.get("/pedidos", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_crud_y_rbac(client):
    ha = auth(client, "alice", "Alice#2026lab")
    hb = auth(client, "bob", "Bob#2026lab")
    hadm = auth(client, "admin", "Adm1n#2026lab")
    pid = client.post("/pedidos", json={"producto": "Webcam HD", "cantidad": 2}, headers=ha).json()["id"]
    assert client.put(f"/pedidos/{pid}", json={"producto": "Webcam HD", "cantidad": 3}, headers=ha).status_code == 200
    assert client.put(f"/pedidos/{pid}", json={"producto": "Gratis", "cantidad": 9}, headers=hb).status_code == 404
    assert client.put(f"/pedidos/{pid}", json={"producto": "X", "cantidad": -1}, headers=ha).status_code == 422
    assert client.delete(f"/pedidos/{pid}", headers=ha).status_code == 403
    assert client.delete(f"/pedidos/{pid}", headers=hadm).status_code == 200
    assert client.delete("/pedidos/{$ne:1}", headers=hadm).status_code == 422


@pytest.mark.parametrize("qs", ["q=*", "q=coste_interno:>500", "q=portatil&size=1000", "q=a"])
def test_busqueda_rechaza_lucene_y_paginacion_abusiva(client, qs):
    assert client.get(f"/articulos?{qs}").status_code == 422


def test_busqueda_usa_multi_match_paginada_y_campos_limitados(client):
    r = client.get("/articulos?q=portatil&page=2&size=5")
    assert r.status_code == 200
    body = client.sent["body"]
    assert "multi_match" in body["query"] and "query_string" not in str(body)
    assert body["from"] == 5 and body["size"] == 5
    assert "coste_interno" not in body["_source"]


def test_rate_limit_login(client):
    codes = [login(client, "alice", "fuerza_bruta").status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429


def test_cabeceras_de_seguridad(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


def test_docs_desactivadas(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
