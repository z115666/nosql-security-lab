#!/usr/bin/env bash
# EXTENSIÓN CLOUD · MongoDB Atlas (clúster gratuito) con bastionado:
#   - usuario de aplicación con readWrite SOLO sobre "tienda" (no readWriteAnyDatabase)
#   - lista de IP permitidas con una única IP (sin 0.0.0.0/0)
#   - TLS obligatorio (Atlas no admite conexiones en claro)
# Requisito: fichero .env.atlas (ver .env.atlas.example). Nunca se sube a Git.
source "$(dirname "$0")/_lib.sh"
[[ -f .env.atlas ]] || { echo "Falta .env.atlas: cópialo de .env.atlas.example y rellénalo"; exit 1; }
set -a; source .env.atlas; set +a
: "${ATLAS_HOST:?Falta ATLAS_HOST}" "${ATLAS_USER:?Falta ATLAS_USER}" "${ATLAS_PASSWORD:?Falta ATLAS_PASSWORD}"
STAMP=$(date +%Y%m%d_%H%M%S)
exec > >(tee "evidencias/05_atlas_$STAMP.txt") 2>&1

OPTS="retryWrites=true&w=majority&appName=nosql-security-lab&serverSelectionTimeoutMS=8000"
URI="mongodb+srv://$ATLAS_USER:$ATLAS_PASSWORD@$ATLAS_HOST/tienda?$OPTS"
URI_SIN_TLS="mongodb+srv://$ATLAS_USER:$ATLAS_PASSWORD@$ATLAS_HOST/tienda?$OPTS&tls=false"
URI_MALA_CLAVE="mongodb+srv://$ATLAS_USER:clave-incorrecta-123@$ATLAS_HOST/tienda?$OPTS"

# mongosh local o, si no está instalado, el del contenedor mongo:7
msh() {  # msh URI [args...]
  if command -v mongosh >/dev/null 2>&1; then mongosh "$@"
  else docker run --rm mongo:7 mongosh "$@"; fi
}
denegado() { grep -qiE 'not authorized|not allowed|Unauthorized|CMD_NOT_ALLOWED' <<<"$1" && echo denegado || echo PERMITIDO; }

banner "EXTENSIÓN CLOUD · MongoDB Atlas ($ATLAS_HOST)"

step "1. Carga idempotente del dataset (usuario de aplicación)"
echo "${Y}\$ mongosh <URI de Atlas> --eval \"\$(cat secure/atlas_seed.js)\"${N}"
msh "$URI" --quiet --eval "$(cat secure/atlas_seed.js)" 2>&1 | tail -2; echo

step "2. Identidad y privilegios efectivos de la conexión"
OUT=$(msh "$URI" --quiet --eval '
  const s = db.runCommand({connectionStatus: 1}).authInfo;
  print("Usuario: " + JSON.stringify(s.authenticatedUsers));
  print("Roles:   " + JSON.stringify(s.authenticatedUserRoles));
  const r = s.authenticatedUserRoles;
  print(r.length === 1 && r[0].role === "readWrite" && r[0].db === "tienda" ? "PRIV=MINIMO" : "PRIV=AMPLIO");' 2>&1)
echo "$OUT" | grep -v '^PRIV='; echo
check "Conexión legítima por TLS (SCRAM)" "ok" "$(grep -q '^PRIV=' <<<"$OUT" && echo ok || echo fallo)"
check "Privilegios mínimos: solo readWrite@tienda" "MINIMO" "$(grep -o 'PRIV=[A-Z]*' <<<"$OUT" | cut -d= -f2)"

step "3. Datos y contraseñas protegidas"
run "msh '$URI' --quiet --eval 'printjson(db.usuarios.findOne({}, {_id:0, username:1, password_hash:1}))' 2>&1"
NBCRYPT=$(msh "$URI" --quiet --eval 'print(db.usuarios.countDocuments({password_hash: /^\$2[aby]\$/}))' 2>&1 | tail -1)
check "Contraseñas almacenadas con bcrypt (usuarios)" "3" "$NBCRYPT"

step "4. TLS del clúster (protocolo, cifrado y certificado)"
NODO=$(msh "$URI" --quiet --eval 'print(db.hello().me)' 2>&1 | tail -1)
echo "Nodo primario: $NODO"
TLSOUT=$(echo | openssl s_client -connect "$NODO" -servername "${NODO%%:*}" 2>/dev/null)
grep -E 'Protocol *:|Cipher is|^issuer=|s:.*CN|i:.*CN' <<<"$TLSOUT" | head -6; echo
check "Protocolo TLS 1.2 o 1.3" "TLSv1\.[23]" "$(grep -oE 'TLSv1\.[0-9]' <<<"$TLSOUT" | head -1)"

step "5. Conexión sin TLS"
OUT=$(msh "$URI_SIN_TLS" --quiet --eval 'print(db.runCommand({ping:1}).ok)' 2>&1)
tail -2 <<<"$OUT" | cut -c1-200; echo
check "Conexión en claro rechazada" "rechazada" "$(tail -1 <<<"$OUT" | grep -qx 1 && echo ACEPTADA || echo rechazada)"

step "6. Contraseña incorrecta"
OUT=$(msh "$URI_MALA_CLAVE" --quiet --eval 'print(db.runCommand({ping:1}).ok)' 2>&1)
tail -2 <<<"$OUT" | cut -c1-200; echo
check "Credenciales incorrectas rechazadas" "rechazada" "$(grep -qiE 'auth.*fail' <<<"$OUT" && echo rechazada || echo ACEPTADA)"

step "7. Mínimo privilegio: lo que el usuario de aplicación NO puede hacer"
OUT=$(msh "$URI" --quiet --eval 'db.getSiblingDB("otra_bd").secretos.find().toArray()' 2>&1); tail -1 <<<"$OUT" | cut -c1-200
check "No lee otras bases de datos" "denegado" "$(denegado "$OUT")"
OUT=$(msh "$URI" --quiet --eval 'db.getSiblingDB("otra_bd").secretos.insertOne({x:1})' 2>&1); tail -1 <<<"$OUT" | cut -c1-200
check "No escribe en otras bases de datos" "denegado" "$(denegado "$OUT")"
OUT=$(msh "$URI" --quiet --eval 'db.createUser({user:"intruso", pwd:"Intruso#2026", roles:["root"]})' 2>&1); tail -1 <<<"$OUT" | cut -c1-200
check "No crea usuarios" "denegado" "$(denegado "$OUT")"
OUT=$(msh "$URI" --quiet --eval 'db.dropDatabase()' 2>&1); tail -1 <<<"$OUT" | cut -c1-200
check "No borra la base de datos" "denegado" "$(denegado "$OUT")"
OUT=$(msh "$URI" --quiet --eval '
  try {
    const d = db.getSiblingDB("admin").runCommand({listDatabases: 1, nameOnly: true});
    const n = (d.databases || []).map(x => x.name);
    print("Bases de datos visibles: " + JSON.stringify(n));
    print(n.every(x => x === "tienda") ? "VIS=RESTRINGIDA" : "VIS=TOTAL");
  } catch (e) { print("Error: " + e.message); print("VIS=RESTRINGIDA"); }' 2>&1)
grep -v '^VIS=' <<<"$OUT" | tail -1 | cut -c1-200
check "Solo ve su propia base de datos (tienda)" "RESTRINGIDA" "$(grep -o 'VIS=[A-Z]*' <<<"$OUT" | cut -d= -f2)"

step "8. Validación de esquema en la nube"
OUT=$(msh "$URI" --quiet --eval 'db.usuarios.insertOne({username:"backdoor", password:"pwned", rol:"admin"})' 2>&1); tail -1 <<<"$OUT" | cut -c1-200
check "Rechaza usuario con contraseña en claro" "rechazado" "$(grep -qi 'failed validation' <<<"$OUT" && echo rechazado || echo ACEPTADO)"

banner "Resumen Atlas: $PASS PASS · $FAIL FAIL"
{ echo "Atlas $(date '+%Y-%m-%d %H:%M:%S %Z') · $PASS PASS · $FAIL FAIL"; printf '%s\n' "${RESUMEN[@]}"; } \
  > "evidencias/05_atlas_resumen_$STAMP.txt"
printf '%s\n' "${RESUMEN[@]}" | column -t -s '|' 2>/dev/null || printf '%s\n' "${RESUMEN[@]}"
exit "$FAIL"
