#!/usr/bin/env bash
# FASE 1 · Smoke test del baseline inseguro: servicios arriba, datos cargados y CRUD.
source "$(dirname "$0")/_lib.sh"
API=http://$TARGET_HOST:8000
exec > >(tee "evidencias/00_smoke_test_$(date +%Y%m%d_%H%M%S).txt") 2>&1

banner "FASE 1 · Smoke test (baseline inseguro)"
run "docker compose ps"

step "1. Salud de la API"
run "curl -s $API/health"

step "2. Datos de MongoDB (CRUD - Read)"
run "curl -s $API/pedidos | $PY -m json.tool"

step "3. CRUD - Create"
ID=$(curl -s -X POST $API/pedidos -H 'Content-Type: application/json' \
      -d '{"producto":"Webcam HD","cantidad":3}' | $PY -c 'import sys,json;print(json.load(sys.stdin)["id"])')
echo "\$ curl -X POST $API/pedidos -d '{\"producto\":\"Webcam HD\",\"cantidad\":3}'"
echo "Pedido creado con id: $ID"; echo

step "4. CRUD - Update"
run "curl -s -X PUT $API/pedidos/$ID -H 'Content-Type: application/json' -d '{\"producto\":\"Webcam HD\",\"cantidad\":5}'"

step "5. CRUD - Delete"
run "curl -s -X DELETE $API/pedidos/$ID"

step "6. Login legítimo y login fallido"
run "curl -s -X POST $API/login_mongo -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"alice123\"}'"
run "curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST $API/login_mongo -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"mala\"}'"

step "7. Búsqueda en Elasticsearch a través de la API"
run "curl -s '$API/articulos?q=portatil' | $PY -m json.tool | head -40"

echo "${G}Smoke test terminado.${N}"
