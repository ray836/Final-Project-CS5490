# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant

import socket
import Functions


def handle_online_node_connection(online_node_socket, address):
    ssl_handshake(online_node_socket)
    data_transfer(online_node_socket)
    testing_code(online_node_socket)


def ssl_handshake(node_socket):
    pass


def data_transfer(node_socket):
    pass


def testing_code(given_socket):
    test_dict = Functions.read_message_with_delimiter(given_socket)
    print(test_dict)
    print(test_dict["msg"])


# start of program
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 5432))
s.listen()

while True:
    online_node_socket, address = s.accept()
    print(f"Connection from {address}")
    handle_online_node_connection(online_node_socket, address)
