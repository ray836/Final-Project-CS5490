# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant

import socket
import cryptography
import Functions
import Modified_SSL_Handshake

private_key = Functions.generate_private_key()


def perform_online_node_handshake(online_node_socket, address):
    if Modified_SSL_Handshake.server_ssl_handshake(online_node_socket, "Middle Node", private_key):
        data_transfer(online_node_socket)
    else:
        print("handshake failed")


def perform_offline_node_handshake(online_node_socket):
    if Modified_SSL_Handshake.client_ssl_handshake(online_node_socket, "Middle Node", private_key):
        data_transfer(online_node_socket)
    else:
        print("handshake to offline node failed")


def data_transfer(given_socket):
    pass


def handle_online_node_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), 5432))
    s.listen()

    while True:
        online_node_socket, address = s.accept()
        print(f"Connection from {address}")
        perform_online_node_handshake(online_node_socket, address)


def initiate_offline_node_connection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostname(), 5433))
    perform_offline_node_handshake(s)


def main():
    # start of program
    initiate_offline_node_connection()
    # todo: make this multithreded


if __name__ == '__main__':
    main()
