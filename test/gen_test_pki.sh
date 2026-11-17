#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Ferdinand Keil
# SPDX-License-Identifier: MIT
# Erzeugt eine Test-PKI fuer den Host-Test (alle Gueltigkeiten fest: 2024-01-01 .. 2044-01-01):
#   Flache CA:      ca.pem                      -> dev.pem   (Kettenlaenge 2: Geraet + CA)
#   Kette:          root.pem -> inter.pem -> issuing.pem -> dev_chain.pem
#   Geraeteschluessel dev.key (fuer dev.pem und dev_chain.pem identisch)
#   other.pem:      Zertifikat zu einem anderen Schluessel (Negativtest)
#   longca.pem/medca.pem + dev_longdn.pem/dev_meddn.pem: CAs mit sehr langem bzw. mittlerem Issuer-DN (Puffertests)
#   shortca.pem/futureca.pem + dev_shortca.pem/dev_futureca.pem: CA abgelaufen ab 2026-06 bzw. gueltig ab 2026-03
#   leaf_ca.pem:    Zertifikat OHNE CA-Flag, ausgestellt von der Test-CA (Negativtest CA-Flag)
# Aufruf: gen_test_pki.sh <ausgabeverzeichnis>
set -euo pipefail
out="${1:?Ausgabeverzeichnis fehlt}"
mkdir -p "$out"; cd "$out"
rm -rf db_* ./*.pem ./*.key ./*.csr tsa.cnf tsa_serial

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
[pol_any]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
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
[ext_tsa]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ext_dev]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

mkkey() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; }
newdb() { mkdir "db_$1"; : > "db_$1/index.txt"; echo "$2" > "db_$1/serial"; }

# issue <ausstellername> <ausstellerzert|""> <csr> <ext> <out> [policy]   (leer = selbstsigniert)
issue() {
  local issuer="$1" issuer_pem="$2" csr="$3" ext="$4" outpem="$5" policy="${6:-pol}"
  local start="${7:-20240101000000Z}" end="${8:-20440101000000Z}"
  local args=(-batch -config ca.cnf -policy "$policy" -keyfile "$issuer.key" -in "$csr" -extensions "$ext"
              -startdate "$start" -enddate "$end" -notext -out "$outpem")
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

# Zertifikate mit langem Issuer-DN (Probe-Build beim Import): longca ~375 Byte DN (passt nicht in einen
# Attribut-Puffer von 512 Byte), medca ~200 Byte (passt). Beide von der flachen CA ausgestellt.
rep() { printf "$1%.0s" $(seq 1 "$2"); }
mkkey longca; newdb longca 5000
mkcsr longca "/C=DE/ST=$(rep s 64)/L=$(rep l 64)/O=$(rep o 64)/OU=$(rep u 64)/CN=$(rep c 64)"
issue ca ca.pem longca.csr ext_ca longca.pem pol_any
issue longca longca.pem dev.csr ext_dev dev_longdn.pem
mkkey medca; newdb medca 6000
mkcsr medca "/C=DE/O=$(rep o 64)/OU=$(rep u 64)/CN=$(rep c 40)"
issue ca ca.pem medca.csr ext_ca medca.pem pol_any
issue medca medca.pem dev.csr ext_dev dev_meddn.pem

# CAs mit abweichender Gueltigkeit (Pruefung der Kette beim Signieren):
#   shortca: abgelaufen ab 2026-06-01, futureca: gueltig erst ab 2026-03-01
mkkey shortca; newdb shortca 7000; mkcsr shortca "/C=DE/O=Test Org/CN=Test Short CA"
issue ca ca.pem shortca.csr ext_ca shortca.pem pol 20240101000000Z 20260601000000Z
issue shortca shortca.pem dev.csr ext_dev dev_shortca.pem
mkkey futureca; newdb futureca 8000; mkcsr futureca "/C=DE/O=Test Org/CN=Test Future CA"
issue ca ca.pem futureca.csr ext_ca futureca.pem pol 20260301000000Z 20440101000000Z
issue futureca futureca.pem dev.csr ext_dev dev_futureca.pem

# --- Test-TSA (RFC 3161) -----------------------------------------------------------------------------
#   tsa_root.pem / tsa_root2.pem: zwei unabhaengige TSA-Root-CAs (tsa_root2 = "fremde" CA)
#   tsa.pem:        TSA-Zertifikat (EC P-256) mit kritischer EKU timeStamping, von tsa_root
#   tsa_noeku.pem:  gleicher Schluessel, aber OHNE EKU (Negativtest; openssl ts -reply kann damit nicht
#                   antworten, der Test baut die Antwort per openssl cms -sign)
#   tsa_foreign.pem: gleicher Schluessel, EKU ok, aber von tsa_root2 (fremde CA)
#   tsa.cnf:        Konfiguration fuer "openssl ts -reply" (Sektionen tsa_good, tsa_foreign)
mkkey tsa_root;  newdb tsa_root 9000;  mkcsr tsa_root "/C=DE/O=Test Org/CN=Test TSA Root"
issue tsa_root "" tsa_root.csr ext_root tsa_root.pem
mkkey tsa_root2; newdb tsa_root2 9500; mkcsr tsa_root2 "/C=DE/O=Test Org/CN=Fremde TSA Root"
issue tsa_root2 "" tsa_root2.csr ext_root tsa_root2.pem
mkkey tsa; mkcsr tsa "/C=DE/O=Test Org/CN=Test TSA"
issue tsa_root tsa_root.pem tsa.csr ext_tsa tsa.pem
issue tsa_root tsa_root.pem tsa.csr ext_dev tsa_noeku.pem
issue tsa_root2 tsa_root2.pem tsa.csr ext_tsa tsa_foreign.pem
: > tsa_serial; echo 01 > tsa_serial
for s in good foreign; do
  case $s in good) cert=tsa.pem; chain=tsa_root.pem;; foreign) cert=tsa_foreign.pem; chain=tsa_root2.pem;; esac
  cat >> tsa.cnf <<CNF
[tsa_$s]
serial = $out/tsa_serial
crypto_device = builtin
signer_cert = $out/$cert
certs = $out/$chain
signer_key = $out/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.5
other_policies = 1.2.3.4.6
digests = sha256, sha384
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
CNF
done
echo "PKI in $out"
