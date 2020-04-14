# Offline Node
# Bruce Englert, Meghana Gupta, Ray Grant

import socket


def handle_middle_node_connection(middle_node_socket, address):
    ssl_handshake(middle_node_socket)
    data_transfer(middle_node_socket)


def ssl_handshake(middle_node_socket):
    pass


def data_transfer(middle_node_socket):
    pass


# start of program
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 5433))
s.listen()

while True:
    middle_node_socket, address = s.accept()
    print(f"Connection from {address}")
    handle_middle_node_connection(middle_node_socket, address)