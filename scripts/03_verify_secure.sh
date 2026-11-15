#!/usr/bin/env bash
# FASE 6 · Verificación: se repiten los ataques contra el escenario endurecido.
# Todos deben FALLAR (401/403/422/429 o conexión rechazada) y quedar registrados.
source "$(dirname "$0")/_lib.sh"
[[ -f .env ]] || { echo "Falta .env: ejecuta scripts/gen_env.sh"; exit 1; }
set -a; source .env; set +a
DC="docker compose -f docker-compose.secure.yml"
API=https://$TARGET_HOST:8443
CURL="curl -s --cacert certs/ca.crt"
J='-H Content-Type:application/json'
STAMP=$(date +%Y%m%d_%H%M%S)
exec > >(tee "evidencias/03_verify_$STAMP.txt") 2>&1

code() { $CURL -o /dev/null -w '%{http_code}' "$@"; }
port_state() { (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && echo abierto || echo cerrado; }
token() {
  $CURL -X POST $API/login_mongo $J -d "{\"username\":\"$1\",\"password\":\"$2\"}" |
    $PY -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))'
}
mongo_root() { $DC exec -T mongo mongosh --quiet --tls --tlsCAFile /certs/ca.crt --host localhost "$@"; }
es_curl() { $DC exec -T elasticsearch curl -s --cacert config/certs/ca.crt "$@"; }

banner "FASE 6 · Verificación del escenario endurecido"
run "$DC ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'"

# ------------------------------------------------------------------ V0
step "V0. Superficie expuesta y TLS"
for p in 27017 9200 8000; do check "Puerto $p cerrado en el host" "cerrado" "$(port_state $p)"; done
check "Puerto 8443 (nginx TLS) abierto" "abierto" "$(port_state 8443)"
run "echo | openssl s_client -connect $TARGET_HOST:8443 -servername localhost -CAfile certs/ca.crt 2>/dev/null | grep -E 'Protocol|Cipher is|Verify return code' | sort -u"
TLSV=$(echo | openssl s_client -connect $TARGET_HOST:8443 -servername localhost -CAfile certs/ca.crt 2>/dev/null | grep -c 'Verify return code: 0')
check "Certificado TLS válido contra la CA del laboratorio" "[1-9][0-9]*" "$TLSV"
check "HTTP en claro contra el puerto TLS rechazado" "400" "$(curl -s -o /dev/null -w '%{http_code}' http://$TARGET_HOST:8443/health)"
check "TLS 1.0 rechazado" "000" "$(curl -s -o /dev/null -w '%{http_code}' --tlsv1.0 --tls-max 1.0 --cacert certs/ca.crt $API/health)"

# ------------------------------------------------------------------ V1
step "V1. NoSQL Injection en /login_mongo"
run "$CURL -X POST $API/login_mongo $J -d '{\"username\":\"alice\",\"password\":{\"\$ne\":\"x\"}}'"
check "NoSQLi password {\$ne}" "422" "$(code -X POST $API/login_mongo $J -d '{"username":"alice","password":{"$ne":"x"}}')"
check "NoSQLi {\$ne:null} en ambos campos" "422" "$(code -X POST $API/login_mongo $J -d '{"username":{"$ne":null},"password":{"$ne":null}}')"
check "NoSQLi \$regex sobre admin" "422" "$(code -X POST $API/login_mongo $J -d '{"username":{"$regex":"^adm"},"password":{"$gt":""}}')"
check "Campo extra no permitido" "422" "$(code -X POST $API/login_mongo $J -d '{"username":"alice","password":"x123456","rol":"admin"}')"
check "Operador como texto literal => solo credenciales malas" "401" "$(code -X POST $API/login_mongo $J -d '{"username":"alice","password":"$ne:xxxx"}')"

# ------------------------------------------------------------------ V2
step "V2. Autenticación (bcrypt + JWT)"
check "Login con contraseña incorrecta" "401" "$(code -X POST $API/login_mongo $J -d '{"username":"alice","password":"incorrecta"}')"
T_ALICE=$(token alice 'Alice#2026lab'); T_BOB=$(token bob 'Bob#2026lab'); T_ADMIN=$(token admin 'Adm1n#2026lab')
check "Login legítimo de alice devuelve JWT" "eyJ.*" "${T_ALICE:-vacio}"
echo "JWT de alice (cabecera.carga): $(echo "$T_ALICE" | cut -d. -f1-2 | cut -c1-60)..."

# ------------------------------------------------------------------ V3
step "V3. Autorización (RBAC de aplicación) y CRUD"
check "GET /pedidos sin token" "401" "$(code $API/pedidos)"
check "GET /pedidos con token falsificado" "401" "$(code -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbCI6ImFkbWluIn0.' $API/pedidos)"
run "$CURL -H 'Authorization: Bearer $T_ALICE' '$API/pedidos?size=5' | $PY -m json.tool"
AJENOS=$($CURL -H "Authorization: Bearer $T_ALICE" "$API/pedidos?size=50" | $PY -c 'import sys,json; print(sum(1 for p in json.load(sys.stdin)["items"] if p["usuario"]!="alice"))')
check "alice solo ve sus pedidos (pedidos ajenos visibles)" "0" "$AJENOS"
NEW=$($CURL -X POST $API/pedidos $J -H "Authorization: Bearer $T_ALICE" -d '{"producto":"Webcam HD","cantidad":2}' | $PY -c 'import sys,json; print(json.load(sys.stdin).get("id",""))')
check "CRUD Create (alice)" "[a-f0-9]{24}" "${NEW:-vacio}"
check "CRUD Update de su propio pedido" "200" "$(code -X PUT $API/pedidos/$NEW $J -H "Authorization: Bearer $T_ALICE" -d '{"producto":"Webcam HD","cantidad":4}')"
check "bob intenta modificar el pedido de alice" "404" "$(code -X PUT $API/pedidos/$NEW $J -H "Authorization: Bearer $T_BOB" -d '{"producto":"Gratis","cantidad":999}')"
check "Cantidad fuera de rango (validación)" "422" "$(code -X PUT $API/pedidos/$NEW $J -H "Authorization: Bearer $T_ALICE" -d '{"producto":"Webcam HD","cantidad":-5}')"
check "alice intenta borrar (rol cliente)" "403" "$(code -X DELETE $API/pedidos/$NEW -H "Authorization: Bearer $T_ALICE")"
check "CRUD Delete por admin" "200" "$(code -X DELETE $API/pedidos/$NEW -H "Authorization: Bearer $T_ADMIN")"
check "Id con operador en la ruta" "422" "$(code -X DELETE "$API/pedidos/%7B%24ne%3A1%7D" -H "Authorization: Bearer $T_ADMIN")"

# ------------------------------------------------------------------ V4
step "V4. Búsqueda en Elasticsearch a través de la API"
check "q=* (volcado completo)" "422" "$(code "$API/articulos?q=*")"
check "q con sintaxis Lucene (coste_interno:>500)" "422" "$(code "$API/articulos?q=coste_interno:%3E500")"
check "size=1000 (sin paginar)" "422" "$(code "$API/articulos?q=portatil&size=1000")"
run "$CURL '$API/articulos?q=portatil&size=5' | $PY -m json.tool"
FUGA=$($CURL "$API/articulos?q=portatil" | grep -c coste_interno)
check "La respuesta no incluye coste_interno" "0" "$FUGA"

# ------------------------------------------------------------------ V5
step "V5. MongoDB: acceso anónimo, sin TLS y mínimo privilegio"
OUT=$(mongo_root tienda --eval 'db.usuarios.find().toArray()' 2>&1); echo "$OUT" | tail -2
check "Lectura anónima (con TLS) denegada" "denegado" "$(echo "$OUT" | grep -qiE 'requires authentication|unauthorized' && echo denegado || echo PERMITIDO)"
OUT=$($DC exec -T mongo mongosh --quiet "mongodb://localhost:27017/tienda?serverSelectionTimeoutMS=3000" --eval 'db.runCommand({ping:1})' 2>&1); echo "$OUT" | tail -2
check "Conexión sin TLS rechazada" "rechazada" "$(echo "$OUT" | grep -q '"ok"\|ok: 1' && echo ACEPTADA || echo rechazada)"
APP="-u $MONGO_APP_USER -p $MONGO_APP_PASSWORD --authenticationDatabase tienda"
run "mongo_root tienda $APP --eval 'printjson(db.usuarios.findOne({}, {_id:0, username:1, password_hash:1}))' 2>&1"
OUT=$(mongo_root tienda $APP --eval 'db.getSiblingDB("admin").system.users.find().toArray()' 2>&1); echo "$OUT" | tail -1
check "Usuario app no lee admin.system.users" "denegado" "$(echo "$OUT" | grep -qi 'not authorized' && echo denegado || echo PERMITIDO)"
OUT=$(mongo_root tienda $APP --eval 'db.dropDatabase()' 2>&1); echo "$OUT" | tail -1
check "Usuario app no puede borrar la BD" "denegado" "$(echo "$OUT" | grep -qi 'not authorized' && echo denegado || echo PERMITIDO)"
OUT=$(mongo_root tienda $APP --eval 'db.createUser({user:"x",pwd:"x",roles:["root"]})' 2>&1); echo "$OUT" | tail -1
check "Usuario app no puede crear usuarios" "denegado" "$(echo "$OUT" | grep -qi 'not authorized' && echo denegado || echo PERMITIDO)"
OUT=$(mongo_root tienda $APP --eval 'db.usuarios.insertOne({username:"backdoor",password:"pwned",rol:"admin"})' 2>&1); echo "$OUT" | tail -1
check "Esquema rechaza usuario con contraseña en claro" "rechazado" "$(echo "$OUT" | grep -qi 'failed validation' && echo rechazado || echo ACEPTADO)"

# ------------------------------------------------------------------ V6
step "V6. Elasticsearch: autenticación, TLS y RBAC"
check "Búsqueda anónima" "401" "$(es_curl -o /dev/null -w '%{http_code}' 'https://localhost:9200/articulos/_search?q=*')"
check "HTTP sin TLS" "000|52" "$($DC exec -T elasticsearch curl -s -o /dev/null -w '%{http_code}' http://localhost:9200/ ; echo -n)"
check "api_lector busca en articulos" "200" "$(es_curl -o /dev/null -w '%{http_code}' -u "$ES_APP_USER:$ES_APP_PASSWORD" 'https://localhost:9200/articulos/_search?size=1')"
check "api_lector lista índices (_cat/indices)" "403" "$(es_curl -o /dev/null -w '%{http_code}' -u "$ES_APP_USER:$ES_APP_PASSWORD" https://localhost:9200/_cat/indices)"
check "api_lector escribe un documento" "403" "$(es_curl -o /dev/null -w '%{http_code}' -u "$ES_APP_USER:$ES_APP_PASSWORD" -XPUT -H 'Content-Type: application/json' https://localhost:9200/articulos/_doc/99 -d '{"nombre":"x"}')"
check "api_lector DELETE del índice" "403" "$(es_curl -o /dev/null -w '%{http_code}' -u "$ES_APP_USER:$ES_APP_PASSWORD" -XDELETE https://localhost:9200/articulos)"
run "es_curl -u '$ES_APP_USER:$ES_APP_PASSWORD' -XDELETE https://localhost:9200/articulos; echo"

# ------------------------------------------------------------------ V7
step "V7. Rate limiting y alertas"
CODES=""; for _ in $(seq 1 12); do CODES+="$(code -X POST $API/login_mongo $J -d '{"username":"alice","password":"fuerza_bruta"}') "; done
echo "Códigos de 12 intentos de login fallidos: $CODES"
check "Fuerza bruta en login acaba en 429" "429" "$(echo $CODES | awk '{print $NF}')"
CODES=""; for _ in $(seq 1 32); do CODES+="$(code "$API/articulos?q=monitor") "; done
echo "Códigos de 32 búsquedas seguidas: $CODES"
check "Pico de búsquedas acaba en 429" "429" "$(echo $CODES | awk '{print $NF}')"

# ------------------------------------------------------------------ V8
step "V8. Trazabilidad: los ataques quedan registrados"
sleep 1
run "grep -hE 'nosqli_blocked|validation_rejected|login_fail|auth_missing|auth_invalid|forbidden|rate_limited|ALERTA' logs/security.log | tail -15"
for ev in nosqli_blocked login_fail forbidden rate_limited ALERTA_FUERZA_BRUTA_LOGIN ALERTA_PICO_BUSQUEDAS; do
  n=$(grep -c "\"event\": \"$ev\"" logs/security.log 2>/dev/null || echo 0)
  check "Evento $ev registrado" "[1-9][0-9]*" "$n"
done
run "$DC logs --no-log-prefix nginx 2>/dev/null | grep -E '\" (401|403|422|429) ' | tail -6"
run "$DC logs --no-log-prefix mongo 2>/dev/null | grep -iE 'Authentication failed|Unauthorized|not authorized' | tail -3 | cut -c1-300"

# ------------------------------------------------------------------ fin
banner "Resumen: $PASS PASS · $FAIL FAIL"
{ echo "Verificación $(date '+%Y-%m-%d %H:%M:%S %Z') · $PASS PASS · $FAIL FAIL"; printf '%s\n' "${RESUMEN[@]}"; } \
  > "evidencias/03_verify_resumen_$STAMP.txt"
printf '%s\n' "${RESUMEN[@]}" | column -t -s '|' 2>/dev/null || printf '%s\n' "${RESUMEN[@]}"
exit $FAIL
