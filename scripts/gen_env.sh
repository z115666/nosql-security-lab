#!/usr/bin/env bash
# Crea .env con secretos aleatorios para el escenario endurecido.
# Ningún secreto se escribe en el código ni en Git (.env está en .gitignore).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env && "${1:-}" != "--force" ]]; then
  echo ".env ya existe (usa --force para regenerarlo; si ya levantaste el stack,"
  echo "haz antes: docker compose -f docker-compose.secure.yml down -v)"; exit 0
fi

rnd() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }

cat > .env <<EOF
# Generado por scripts/gen_env.sh el $(date '+%Y-%m-%d %H:%M')
MONGO_ROOT_USER=root_admin
MONGO_ROOT_PASSWORD=$(rnd 32)
MONGO_APP_USER=app_tienda
MONGO_APP_PASSWORD=$(rnd 32)
ELASTIC_PASSWORD=$(rnd 32)
ES_APP_USER=api_lector
ES_APP_PASSWORD=$(rnd 32)
JWT_SECRET=$(rnd 64)
EOF
chmod 600 .env
mkdir -p logs backups && chmod 777 logs   # el contenedor escribe logs con un UID sin privilegios
echo ".env creado (permisos 600). Usuarios: root_admin, app_tienda, api_lector."
