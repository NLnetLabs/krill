# PyKMIP test server.

This directory contains configuration and data files for running the PyKMIP KMIP compatible software HSM tool.

PyKMIP is needed by Krill tests that are by disabled by default because they require KMIP compatible HSM reachable at 127.0.0.1:5696 which is likely not available on developer machines.

To prevent the tests running by default they are guarded by a `hsm-tests-kmip` Rust compile-time feature gate.

## Running the tests.

Tested on Fedora Linux 44.

First, verify that the KMIP related tests can be built successfully:

```
cargo build --tests --no-default-features --features hsm,hsm-tests-kmip
```

Next, install and run PyKMIP inside a Python 3.11 (needed by PyKMIP) virtual environment:

```
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python 3.11
source .venv/bin/activate
cd test-resources/pykmip
uv pip install pykmip --constraint ./constraints.txt
python ./run-server.py &
```

Now test that the PyKMIP server can be connected to, at least as via TLS:

```
sleep 5s
openssl s_client -connect 127.0.0.1:5696 || true
```

Finally, run the test suite with the PyKMIP dependent tests enabled:

```
cd -
cargo test --no-default-features --features hsm,hsm-tests-kmip -- --test-threads=1 2>&1
```

The output should include lines like this for tests that use the KMIP server:

```
2026-10-22 14:58:08 [INFO] [krill::commons::crypto::signing::signers::kmip::signer] [(test mode) Default KMIP signer] Using KMIP server 'PyKMIP 0.11.0 Software Server' at 127.0.0.1:5696
```

And the generated `test-resources/pykmip/server.log` file should show the server being used, e.g.:

```
$ grep Processing test-resources/pykmip/server.log
2026-10-22 14:59:14,489 - kmip.server.engine - INFO - Processing operation: ModifyAttribute
2026-10-22 14:59:14,491 - kmip.server.engine - INFO - Processing operation: ModifyAttribute
2026-10-22 14:59:14,494 - kmip.server.engine - INFO - Processing operation: Activate
2026-10-22 14:59:14,495 - kmip.server.engine - INFO - Processing operation: Get
2026-10-22 14:59:14,497 - kmip.server.engine - INFO - Processing operation: Sign
2026-10-22 14:59:14,520 - kmip.server.engine - INFO - Processing operation: CreateKeyPair
2026-10-22 14:59:14,558 - kmip.server.engine - INFO - Processing operation: Get
2026-10-22 14:59:14,560 - kmip.server.engine - INFO - Processing operation: ModifyAttribute
2026-10-22 14:59:14,562 - kmip.server.engine - INFO - Processing operation: ModifyAttribute
2026-10-22 14:59:14,565 - kmip.server.engine - INFO - Processing operation: Activate
2026-10-22 14:59:14,567 - kmip.server.engine - INFO - Processing operation: Get
...
```

## Re-generating the TLS certificates used by the test

If the TLS certificates expire, they can be regenerated like so:

NOTE: These commands were originally run on Ubuntu 18.04 and have not been verified since then.

```
mkdir demoCA
touch demoCA/index.txt
echo 01 > demoCA/serial
openssl ecparam -out ca.key -name secp256r1 -genkey
openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650 -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
openssl ecparam -out server.in.key -name secp256r1 -genkey
openssl req -new -nodes -key server.in.key -outform pem -out server.csr -subj "/C=NL/ST=Noord Holland/L=Amsterdam/O=NLnet Labs/CN=localhost"
OPENSSL_CONF=openssl.cnf openssl ca -keyfile ca.key -cert ca.crt -in server.csr -out server.crt -outdir . -batch -noemailDN -extfile san.cnf -extensions ext -days 3650
openssl pkcs8 -topk8 -nocrypt -in server.in.key -out server.key
```
