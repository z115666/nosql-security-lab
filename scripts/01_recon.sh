#!/usr/bin/env bash
# FASE 2 · Reconocimiento del baseline: puertos/alcance, ausencia de auth y TLS,
# privilegios con los que trabaja la app y logging por defecto.
source "$(dirname "$0")/_lib.sh"
exec > >(tee "evidencias/01_recon_$(date +%Y%m%d_%H%M%S).txt") 2>&1

banner "FASE 2 · Reconocimiento (baseline inseguro)"

step "1. Puertos publicados por los contenedores"
run "docker compose ps --format 'table {{.Service}}\t{{.Ports}}'"

step "2. Escaneo de puertos del host"
if command -v nmap >/dev/null 2>&1; then
  run "nmap -Pn -sV -p 8000,9200,27017 $TARGET_HOST"
else
  for p in 8000 9200 27017; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then echo "Puerto $p/tcp ABIERTO"; else echo "Puerto $p/tcp cerrado"; fi
  done; echo
fi
echo "Escucha en 0.0.0.0 (todas las interfaces => también accesible desde la LAN):"
run "docker inspect -f '{{.Name}} {{json .HostConfig.PortBindings}}' \$(docker compose ps -q)"

step "3. Elasticsearch: banner, versión y estado de la seguridad"
run "curl -s http://$TARGET_HOST:9200"
run "curl -s 'http://$TARGET_HOST:9200/_nodes/settings?filter_path=**.xpack.security&pretty'"
run "curl -s http://$TARGET_HOST:9200/_security/_authenticate"
run "curl -s 'http://$TARGET_HOST:9200/_cluster/health?pretty'"

step "4. MongoDB: conexión anónima desde el host"
run "mongosh_host 'mongodb://localhost:27017/tienda' --quiet --eval 'printjson(db.runCommand({connectionStatus:1}).authInfo); print(\"Usuarios definidos en la BD: \" + db.getUsers().users.length); print(\"Bases de datos visibles: \" + db.adminCommand({listDatabases:1}).databases.map(d=>d.name).join(\", \"))'"
run "mongosh_host 'mongodb://localhost:27017/admin' --quiet --eval 'printjson(db.adminCommand({getCmdLineOpts:1}).parsed)'"

step "5. Ausencia de TLS"
run "echo | openssl s_client -connect $TARGET_HOST:9200 2>&1 | head -5"
run "curl -sv https://$TARGET_HOST:9200 2>&1 | tail -3"
run "curl -sI http://$TARGET_HOST:8000/health | head -1"

step "6. Privilegios con los que trabaja la API"
echo "La API se conecta sin credenciales (MongoClient(host, 27017)): tiene los mismos"
echo "privilegios que cualquier cliente anónimo, es decir, acceso TOTAL a todas las BD."
run "grep -n 'MongoClient\|9200' fastapi-app/app/main_vulnerable.py"
run "docker compose exec -T fastapi-app id"

step "7. Logging por defecto"
run "mongosh_host 'mongodb://localhost:27017/admin' --quiet --eval 'printjson({nivel_log: db.adminCommand({getParameter:1, logLevel:1}).logLevel, profiler: db.getSiblingDB(\"tienda\").getProfilingStatus()})'"
run "docker compose logs --tail 5 mongo"
run "curl -s 'http://$TARGET_HOST:9200/_cluster/settings?include_defaults=true&filter_path=**.audit*,**.slowlog*&pretty' | head -20"
run "docker compose logs --tail 5 fastapi-app"
echo "Conclusión: sin auditoría, sin registro de accesos por usuario y sin alertas."
