#!/usr/bin/env bash
# Utilidades comunes: cabeceras con fecha, eco del comando y guardado de evidencias.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
# Git Bash (Windows) convierte argumentos tipo /ruta en C:/Program Files/Git/ruta: se desactiva
export MSYS_NO_PATHCONV=1
mkdir -p evidencias

if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else B=; G=; R=; Y=; C=; N=; fi

# shellcheck disable=SC2034  # variables usadas por los scripts que hacen "source"
TARGET_HOST=localhost   # los scripts SOLO atacan el propio equipo
# shellcheck disable=SC2034
PY=""   # primer intérprete que funcione de verdad (en Windows "python3" puede ser un acceso falso de la Store)
for _c in python3 python py; do
  if "$_c" -c "import json" >/dev/null 2>&1; then PY=$_c; break; fi
done
[[ -n "$PY" ]] || echo "AVISO: no se encontró Python 3 (necesario para formatear JSON)"

banner() { echo; echo "${B}${C}=== $* ===${N}"; echo "${C}$(date '+%Y-%m-%d %H:%M:%S %Z') · $(hostname)${N}"; }
step()   { echo; echo "${B}--- $* ---${N}"; }
# mask: oculta secretos de .env y tokens JWT en lo que se imprime (capturas sin credenciales)
mask() {
  local s="$*" v
  for v in MONGO_ROOT_PASSWORD MONGO_APP_PASSWORD ELASTIC_PASSWORD ES_APP_PASSWORD JWT_SECRET; do
    [[ -n "${!v:-}" ]] && s=${s//${!v}/****}
  done
  printf '%s\n' "$s" | sed -E 's/(eyJ[A-Za-z0-9_-]{8})[A-Za-z0-9._-]*/\1…/g'
}
run()    { echo "${Y}\$ $(mask "$*")${N}"; eval "$*"; local rc=$?; echo; return $rc; }

# check DESCRIPCIÓN CÓDIGO_ESPERADO CÓDIGO_OBTENIDO  -> línea PASS/FAIL y resumen
PASS=0; FAIL=0; RESUMEN=()
check() {
  local desc=$1 want=$2 got=$3
  if [[ "$got" =~ ^($want)$ ]]; then
    echo "${G}PASS${N}  $desc  (esperado $want, obtenido $got)"; PASS=$((PASS+1))
    RESUMEN+=("PASS | $desc | esperado $want | obtenido $got")
  else
    echo "${R}FAIL${N}  $desc  (esperado $want, obtenido $got)"; FAIL=$((FAIL+1))
    RESUMEN+=("FAIL | $desc | esperado $want | obtenido $got")
  fi
}

# Cliente mongosh: el local si existe; si no, un contenedor efímero que sale por el host.
mongosh_host() {  # mongosh_host URI [args...]
  if command -v mongosh >/dev/null 2>&1; then mongosh "$@"
  else
    local uri=${1/localhost/host.docker.internal}; shift
    docker run --rm --add-host=host.docker.internal:host-gateway mongo:7 mongosh "$uri" "$@"
  fi
}
