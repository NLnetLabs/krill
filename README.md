# RPKI Publication Server

Publication Server for the RPKI

See:
https://tools.ietf.org/html/rfc8181 (Publication Protocol)
https://tools.ietf.org/html/rfc8183 (Identity Exchange and config)

## Dev quick start

Install RUST:
```bash
curl https://sh.rustup.rs -sSf | sh
```

Build the binaries:
```bash
cd $project
cargo build
```

To run the publication server with two example clients:
```bash
 ./target/debug/pubd
```

The server should start on localhost and port 3000.

Some interesting pages:
http://localhost:3000 (shows the not found page)
http://localhost:3000/publishers
http://localhost:3000/publishers/bob

To add static resources, add to the 'static' folder and include static mapping at the end of src/pubd/httpd.rs. You should be able to get to them if you restart the server.








