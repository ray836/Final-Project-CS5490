# Online Node
# Bruce Englert, Meghana Gupta, Ray Grant
# Final Project - Custom MCTLS Offline Server
import pickle
import socket
import time

import cryptography
import Functions
import Modified_SSL_Handshake

private_key = Functions.generate_private_key()


def initial_middle_connection_send_dh():
    middle_socket = Modified_SSL_Handshake.connect_to_node(5432)
    private_dh = Modified_SSL_Handshake.gen_priv_dh_send_pub_dh(middle_socket, "Online Node", private_key)
    return private_dh


def handle_dh_connection(private_dh_key):
    middle_socket = Modified_SSL_Handshake.handle_node_connection(5432)  # TODO: might need to change port

    # DIP - 8
    dh_msg = Functions.read_message_with_delimiter(middle_socket)
    print("[Online Node] Received: ", dh_msg)
    dh_other_key = Functions.load_der_public_key(dh_msg["dh_public_through"], Modified_SSL_Handshake.default_backend())
    shared_dh = Functions.generate_dh_shared_key(private_dh_key, dh_other_key.public_numbers().y)

    return [shared_dh, middle_socket]


def initial_data_transfer(shared_key, node_socket, data):
    # encrypt Data
    [iv, encrypted_data] = Functions.aes_encrypt(shared_key, data)

    encrypted_data = {"iv": iv, "encrypted_data": encrypted_data}

    # Send Data
    print("[Online Node] Sending: ", encrypted_data)
    node_socket.sendall(Functions.wrap_to_send(encrypted_data))
    node_socket.close()


def data_transfer(data):
    pass


stored_data = ["cool"]

private_dh = initial_middle_connection_send_dh()
print("[Online Node] Generated DH part")
[shared_dh, middle_socket] = handle_dh_connection(private_dh)
print("[Online Node] Established DH: ", shared_dh)
initial_data_transfer(shared_dh, middle_socket, pickle.dumps(stored_data))
print("[Online Node] Transferred data")
# start of program
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.connect((socket.gethostname(), 5432))
# private_dh_key = initial_connect_to_middle_node(s)
# s.shutdown(socket.SHUT_RDWR)
# s.close()
#
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.bind((socket.gethostname(), 5431))
# s.listen()
# middle_node_socket, address = s.accept()
# print(f"connetion from {address}")
# pefrorm_handshake(middle_node_socket, private_dh_key)
# shared_dh = handle_dh_and_transfer(middle_node_socket, private_dh_key)
