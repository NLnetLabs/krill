The files created in this directory were created and can be used like so:

Tested on Ubuntu 18:04

```
mkdir demoCA
touch demoCA/index.txt
echo 01 > demoCA/serial
openssl ecparam -out ca.key -name secp256r1 -genkey
openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
openssl ecparam -out server.key -name secp256r1 -genkey
openssl req -new -nodes -key server.key -outform pem -out server.csr -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
OPENSSL_CONF=openssl.cnf openssl ca -keyfile ca.key -cert ca.crt -in server.csr -out server.crt -outdir . -batch -noemailDN -extfile san.cnf -extensions ext -days 3650
openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pkcs8.key

mkdir /etc/pykmip
cp ca.crt server.crt /etc/pykmip/
cp server.pkcs8.key /etc/pykmip/server.key

apt update
apt install -y python3-pip
pip3 install pykmip

cat <<EOF >/etc/pykmip/server.conf
[server]
hostname=localhost
port=5696
certificate_path=/etc/pykmip/server.crt
key_path=/etc/pykmip/server.key
ca_path=/etc/pykmip/ca.crt
auth_suite=TLS1.2
enable_tls_client_auth=False
tls_cipher_suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
logging_level=DEBUG
database_path=/tmp/pykmip.db
EOF

pykmip-server
```
