#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Erzeugt eine Test-PKI fuer den Host-Test (alle Gueltigkeiten fest: 2024-01-01 .. 2044-01-01):
#   Flache CA:      ca.pem                      -> dev.pem   (Kettenlaenge 2: Geraet + CA)
#   Kette:          root.pem -> inter.pem -> issuing.pem -> dev_chain.pem
#   Geraeteschluessel dev.key (fuer dev.pem und dev_chain.pem identisch)
#   other.pem:      Zertifikat zu einem anderen Schluessel (Negativtest)
#   leaf_ca.pem:    Zertifikat OHNE CA-Flag, ausgestellt von der Test-CA (Negativtest CA-Flag)
# Aufruf: gen_test_pki.sh <ausgabeverzeichnis>
set -euo pipefail
out="${1:?Ausgabeverzeichnis fehlt}"
mkdir -p "$out"; cd "$out"
rm -rf db_* ./*.pem ./*.key ./*.csr

cat > ca.cnf <<'CNF'
[ca]
default_ca = CA_default
[CA_default]
dir = .
database = $dir/db_$ENV::CAN/index.txt
new_certs_dir = $dir/db_$ENV::CAN
serial = $dir/db_$ENV::CAN/serial
default_md = sha256
policy = pol
unique_subject = no
copy_extensions = none
[pol]
commonName = supplied
[ext_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ext_root]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ext_dev]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

mkkey() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; }
newdb() { mkdir "db_$1"; : > "db_$1/index.txt"; echo "$2" > "db_$1/serial"; }

# issue <ausstellername> <ausstellerzert|""> <csr> <ext> <out>   (leer = selbstsigniert)
issue() {
  local issuer="$1" issuer_pem="$2" csr="$3" ext="$4" outpem="$5"
  local args=(-batch -config ca.cnf -keyfile "$issuer.key" -in "$csr" -extensions "$ext"
              -startdate 20240101000000Z -enddate 20440101000000Z -notext -out "$outpem")
  if [ -z "$issuer_pem" ]; then args+=(-selfsign); else args+=(-cert "$issuer_pem"); fi
  CAN="$issuer" openssl ca "${args[@]}" 2>/dev/null
}
mkcsr() { openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"; }

# Flache CA + Geraete
mkkey ca; newdb ca 1000
mkcsr ca "/C=DE/O=Test Org/CN=Test CA"; issue ca "" ca.csr ext_root ca.pem
mkkey dev; mkkey other
mkcsr dev "/C=DE/O=Test Org/serialNumber=SN-dev/CN=0123456789AB"
mkcsr other "/C=DE/O=Test Org/serialNumber=SN-other/CN=0123456789AB"
issue ca ca.pem dev.csr ext_dev dev.pem
issue ca ca.pem other.csr ext_dev other.pem
mkkey leaf; mkcsr leaf "/C=DE/O=Test Org/CN=Leaf Kein CA"
issue ca ca.pem leaf.csr ext_dev leaf_ca.pem

# Kette Root -> Intermediate -> Issuing -> Geraet
mkkey root;   newdb root 2000;   mkcsr root "/C=DE/O=Test Org/CN=Test Root"
issue root "" root.csr ext_root root.pem
mkkey inter;  newdb inter 3000;  mkcsr inter "/C=DE/O=Test Org/CN=Test Intermediate"
issue root root.pem inter.csr ext_ca inter.pem
mkkey issuing; newdb issuing 4000; mkcsr issuing "/C=DE/O=Test Org/CN=Test Issuing CA"
issue inter inter.pem issuing.csr ext_ca issuing.pem
issue issuing issuing.pem dev.csr ext_dev dev_chain.pem
echo "PKI in $out"
