#!/bin/sh
# Carga el índice de prueba "articulos" en Elasticsearch.
# Sirve para los dos escenarios:
#   - Inseguro: ES_URL=http://elasticsearch:9200 (sin credenciales)
#   - Seguro:   ES_URL=https://elasticsearch:9200 + ES_USER/ES_PASS + ES_CACERT
#               y CREATE_RBAC=true para crear un rol y un usuario de solo lectura.
set -eu

ES_URL="${ES_URL:-http://elasticsearch:9200}"
ES_USER="${ES_USER:-}"
ES_PASS="${ES_PASS:-}"
ES_CACERT="${ES_CACERT:-}"
CREATE_RBAC="${CREATE_RBAC:-false}"

es() {  # es MÉTODO RUTA [cuerpo]
  set -- -sS -X "$1" "$ES_URL$2" -H "Content-Type: application/json" ${3:+--data-binary "$3"}
  [ -n "$ES_CACERT" ] && set -- --cacert "$ES_CACERT" "$@"
  if [ -n "$ES_USER" ]; then curl -u "$ES_USER:$ES_PASS" "$@"; else curl "$@"; fi
}

code() {  # código HTTP de un GET/HEAD
  set -- -s -o /dev/null -w "%{http_code}" -I "$ES_URL$1"
  [ -n "$ES_CACERT" ] && set -- --cacert "$ES_CACERT" "$@"
  if [ -n "$ES_USER" ]; then curl -u "$ES_USER:$ES_PASS" "$@"; else curl "$@"; fi
}

echo "[es-init] Esperando a Elasticsearch en $ES_URL ..."
i=0
until [ "$(code /_cluster/health)" = "200" ]; do
  i=$((i+1)); [ "$i" -gt 60 ] && { echo "[es-init] ES no responde"; exit 1; }
  sleep 3
done

if [ "$(code /articulos)" = "200" ]; then
  echo "[es-init] El índice articulos ya existe: no se recarga."
else
  echo "[es-init] Creando índice articulos"
  es PUT /articulos '{
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": { "properties": {
      "nombre":      { "type": "text" },
      "descripcion": { "type": "text" },
      "categoria":   { "type": "keyword" },
      "precio":      { "type": "float" },
      "stock":       { "type": "integer" },
      "coste_interno": { "type": "float" }
    } } }'
  echo
  es POST "/articulos/_bulk?refresh=true" '{"index":{"_id":"1"}}
{"nombre":"Portátil 14 pulgadas","descripcion":"Portátil ligero para oficina","categoria":"informatica","precio":899.0,"stock":12,"coste_interno":610.0}
{"index":{"_id":"2"}}
{"nombre":"Ratón inalámbrico","descripcion":"Ratón ergonómico bluetooth","categoria":"perifericos","precio":19.9,"stock":150,"coste_interno":6.5}
{"index":{"_id":"3"}}
{"nombre":"Monitor 27 pulgadas","descripcion":"Monitor IPS 4K para diseño","categoria":"monitores","precio":249.0,"stock":30,"coste_interno":170.0}
{"index":{"_id":"4"}}
{"nombre":"Teclado mecánico","descripcion":"Teclado con interruptores rojos","categoria":"perifericos","precio":79.9,"stock":45,"coste_interno":41.0}
{"index":{"_id":"5"}}
{"nombre":"Portátil gaming","descripcion":"Portátil con gráfica dedicada","categoria":"informatica","precio":1499.0,"stock":5,"coste_interno":1120.0}
'
  echo
fi

if [ "$CREATE_RBAC" = "true" ]; then
  : "${APP_ES_USER:?Falta APP_ES_USER}" "${APP_ES_PASS:?Falta APP_ES_PASS}"
  echo "[es-init] RBAC: rol articulos_lectura (solo read sobre el índice articulos)"
  es PUT /_security/role/articulos_lectura '{
    "cluster": [],
    "indices": [ {
      "names": ["articulos"],
      "privileges": ["read"]
    } ] }'
  echo
  echo "[es-init] RBAC: usuario $APP_ES_USER con el rol articulos_lectura"
  es PUT "/_security/user/$APP_ES_USER" "{\"password\":\"$APP_ES_PASS\",\"roles\":[\"articulos_lectura\"],\"full_name\":\"API FastAPI (solo lectura)\"}"
  echo
fi

echo "[es-init] Listo."
