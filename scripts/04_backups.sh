#!/usr/bin/env bash
# Endurecimiento ampliado · copias de seguridad del escenario endurecido:
#   - MongoDB: mongodump comprimido (autenticado y por TLS) a ./backups
#   - Elasticsearch: snapshot en el repositorio "fs" registrado en path.repo
source "$(dirname "$0")/_lib.sh"
[[ -f .env ]] || { echo "Falta .env"; exit 1; }
set -a; source .env; set +a
DC="docker compose -f docker-compose.secure.yml"
STAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p backups
exec > >(tee "evidencias/04_backups_$STAMP.txt") 2>&1

banner "Copias de seguridad (MongoDB + snapshot de Elasticsearch)"

step "1. mongodump autenticado por TLS"
$DC exec -T mongo mongodump --quiet --tls --tlsCAFile /certs/ca.crt --host localhost \
  -u "$MONGO_ROOT_USER" -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin \
  --db tienda --archive --gzip > "backups/mongo_tienda_$STAMP.archive.gz"
run "ls -lh backups/mongo_tienda_$STAMP.archive.gz"
run "shasum -a 256 backups/mongo_tienda_$STAMP.archive.gz 2>/dev/null || sha256sum backups/mongo_tienda_$STAMP.archive.gz"
echo "Restaurar: $DC exec -T mongo mongorestore --tls --tlsCAFile /certs/ca.crt --host localhost -u ... --archive --gzip --drop < fichero"

es() { $DC exec -T elasticsearch curl -s --cacert config/certs/ca.crt -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' "$@"; }

step "2. Repositorio de snapshots de Elasticsearch"
run "es -XPUT https://localhost:9200/_snapshot/lab_repo -d '{\"type\":\"fs\",\"settings\":{\"location\":\"/usr/share/elasticsearch/snapshots\",\"compress\":true}}'"

step "3. Snapshot del índice articulos"
run "es -XPUT 'https://localhost:9200/_snapshot/lab_repo/snap-$STAMP?wait_for_completion=true' -d '{\"indices\":\"articulos\",\"include_global_state\":false}' | head -c 400; echo"
run "es 'https://localhost:9200/_cat/snapshots/lab_repo?v'"
echo "Restaurar: POST _snapshot/lab_repo/snap-$STAMP/_restore (tras cerrar o borrar el índice)"
echo "Producción: programar con SLM (_slm/policy) y copiar fuera del host (regla 3-2-1)."
