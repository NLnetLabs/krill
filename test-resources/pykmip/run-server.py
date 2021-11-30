#!/usr/bin/python3
from kmip.services.server import KmipServer

server = KmipServer(
    config_path='./server.conf',
    log_path='./server.log'
)

with server:
    server.serve()
