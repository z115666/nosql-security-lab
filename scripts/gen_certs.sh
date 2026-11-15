#!/usr/bin/env bash
# Genera una CA de laboratorio y los certificados de servidor (SAN) para:
#   api (nginx) · mongo · elasticsearch
# Sintaxis compatible con OpenSSL 1.1/3.x y con LibreSSL (macOS).
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: no convertir "-subj /C=ES/..." en una ruta de Windows
cd "$(dirname "$0")/.."
OUT=certs
DAYS=365
mkdir -p "$OUT"

if [[ -f $OUT/ca.crt && "${1:-}" != "--force" ]]; then
  echo "Ya existen certificados en $OUT/ (usa --force para regenerarlos)"; exit 0
fi

echo "== CA del laboratorio"
openssl genrsa -out $OUT/ca.key 4096 2>/dev/null
openssl req -x509 -new -key $OUT/ca.key -sha256 -days $DAYS \
  -subj "/C=ES/O=UNIR Lab/CN=UNIR NoSQL Lab Root CA" -out $OUT/ca.crt

emitir() {  # emitir NOMBRE "DNS:a,DNS:b,IP:..."
  local n=$1 san=$2
  echo "== Certificado de servidor: $n ($san)"
  openssl genrsa -out $OUT/$n.key 2048 2>/dev/null
  openssl req -new -key $OUT/$n.key -subj "/C=ES/O=UNIR Lab/CN=$n" -out $OUT/$n.csr
  cat > $OUT/$n.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
  openssl x509 -req -in $OUT/$n.csr -CA $OUT/ca.crt -CAkey $OUT/ca.key -CAcreateserial \
    -days $DAYS -sha256 -extfile $OUT/$n.ext -out $OUT/$n.crt 2>/dev/null
  rm -f $OUT/$n.csr $OUT/$n.ext
}

emitir api           "DNS:localhost,IP:127.0.0.1"
emitir mongo         "DNS:mongo,DNS:localhost,IP:127.0.0.1"
emitir elasticsearch "DNS:elasticsearch,DNS:localhost,IP:127.0.0.1"

cat $OUT/mongo.key $OUT/mongo.crt > $OUT/mongo.pem   # formato que pide mongod

# Laboratorio: los contenedores usan UID distintos (mongodb=999, elasticsearch=1000,
# nginx=root), así que las claves deben ser legibles dentro de ellos. En producción
# se montarían como secretos con propietario y permisos 0400.
chmod 644 $OUT/*.key $OUT/*.pem $OUT/*.crt
chmod 600 $OUT/ca.key

echo "== Comprobación"
for n in api mongo elasticsearch; do
  openssl verify -CAfile $OUT/ca.crt $OUT/$n.crt
done
echo "Certificados en $OUT/ (no se suben a Git: ver .gitignore)"
