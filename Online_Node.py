# Online Node
# Bruce Englert, Meghana Gupta, Ray Grant
# Final Project - Custom MCTLS Offline Server

import socket
import Functions


def connect_to_middle_node(middle_node_socket):
    ssl_handshake(middle_node_socket)
    data_transfer(middle_node_socket, "data")


def ssl_handshake(middle_node_socket):
    pass


def data_transfer(middle_node_socket, data):
    pass


def testing_code(given_socket):
    test_dictionary = {"msg": "hello"}
    given_socket.sendall(Functions.wrap_to_send(test_dictionary))


# start of program
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 5432))
connect_to_middle_node(s)

