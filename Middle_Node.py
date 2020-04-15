# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant

import socket
import cryptography
import Functions

private_key = Functions.generate_private_key()


def handle_online_node_connection(online_node_socket, address):
    if Functions.server_ssl_handshake(online_node_socket, "Middle Node", private_key):
        data_transfer(online_node_socket)
    else:
        print("handshake failed")


def connect_to_offline_node(online_node_socket):
    if Functions.client_ssl_handshake(online_node_socket, "Middle Node", private_key):
        data_transfer(online_node_socket)
    else:
        print("handshake to offline node failed")


def data_transfer(given_socket):
    pass


def listen_handle_online_node():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), 5432))
    s.listen()

    while True:
        online_node_socket, address = s.accept()
        print(f"Connection from {address}")
        handle_online_node_connection(online_node_socket, address)


def offline_node_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostname(), 5433))
    connect_to_offline_node(s)


def main():
    # start of program
    offline_node_connection()


if __name__ == '__main__':
    main()
