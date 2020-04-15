# Online Node
# Bruce Englert, Meghana Gupta, Ray Grant
# Final Project - Custom MCTLS Offline Server

import socket
import cryptography
import Functions

private_key = Functions.generate_private_key()

def connect_to_middle_node(middle_node_socket):
    if Functions.client_ssl_handshake(middle_node_socket, "Online Node", private_key):
        data_transfer(middle_node_socket, "data")


def data_transfer(middle_node_socket, data):
    pass


# start of program
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 5432))
connect_to_middle_node(s)
