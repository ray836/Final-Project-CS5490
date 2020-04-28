# Online Node
# Bruce Englert, Meghana Gupta, Ray Grant
# Final Project - Custom MCTLS Offline Server
import pickle
import time

import Functions
import Modified_SSL_Handshake

private_key = Functions.generate_private_key()
middle_shared_key = b''
n = 0
next_time = 0


def receive_n(node_socket):
    global n
    n_msg = Functions.read_message_with_delimiter(node_socket)
    n_bytes = Functions.aes_decrypt(n_msg["n"]["iv"], middle_shared_key, n_msg["n"]["encrypted_n"])
    n = int.from_bytes(n_bytes, byteorder='big')
    print("[Online Node] n received: ", n)


def send_n(node_socket):
    global n
    print("sending", n-1)
    [iv, encrypted_n] = Functions.aes_encrypt(middle_shared_key, bytes([n-1]))
    n_msg = {"n": {"iv": iv, "encrypted_n": encrypted_n}}
    node_socket.sendall(Functions.wrap_to_send(n_msg))


def receive_next_time(node_socket):
    global next_time
    next_t_msg = Functions.read_message_with_delimiter(node_socket)
    next_time_bytes = Functions.aes_decrypt(next_t_msg["next_time"]["iv"], middle_shared_key, next_t_msg["next_time"]["encrypted_time"])
    next_time = int.from_bytes(next_time_bytes, byteorder='big')
    print("received time: ", next_time)


def initial_middle_connection_send_dh():
    global n
    global middle_shared_key

    middle_socket = Modified_SSL_Handshake.connect_to_node(5432)
    [successful_handshake, shared_k] = Modified_SSL_Handshake.client_ssl_handshake(middle_socket, "Online Node", private_key)
    print("[Online Node] Sending DH portion")
    private_dh = Modified_SSL_Handshake.gen_priv_dh_send_pub_dh(middle_socket, "Online Node", private_key)
    middle_shared_key = shared_k

    receive_n(middle_socket)
    receive_next_time(middle_socket)
    return private_dh


def second_dh_connection(private_dh_key):
    print("connecting to middle node...")
    middle_socket = Modified_SSL_Handshake.connect_to_node(5432)  # TODO: might need to change port

    # send authorization n
    send_n(middle_socket)

    dh_msg = Functions.read_message_with_delimiter(middle_socket)
    print("[Online Node] Received: ", dh_msg)
    dh_other_key = Functions.load_der_public_key(dh_msg["dh_public_through"], Modified_SSL_Handshake.default_backend())
    shared_dh = Functions.generate_dh_shared_key(private_dh_key, dh_other_key.public_numbers().y)

    receive_n(middle_socket)
    receive_next_time(middle_socket)
    middle_socket.close()
    return shared_dh


def send_data_transfer(shared_key, data):
    middle_socket = Modified_SSL_Handshake.connect_to_node(5432)
    send_n(middle_socket)

    # encrypt Data
    [iv, encrypted_data] = Functions.aes_encrypt(shared_key, data)
    encrypted_data = {"iv": iv, "encrypted_data": encrypted_data}

    # Send Data
    print("[Online Node] Sending: ", encrypted_data)
    middle_socket.sendall(Functions.wrap_to_send(encrypted_data))
    receive_n(middle_socket)
    receive_next_time(middle_socket)
    middle_socket.close()


stored_data = ["Hello World"]

private_dh = initial_middle_connection_send_dh()
print("[Online Node] Generated DH part")
time.sleep(next_time)
shared_dh = second_dh_connection(private_dh)
print("[Online Node] Established DH: ", shared_dh)

# This sends transfer data 10 times to illustrate real world use.
for i in range(1, 10):
    print("sleeping", next_time)
    time.sleep(next_time)
    print("sending data...")
    send_data_transfer(shared_dh, pickle.dumps(stored_data))
    print("[Online Node] Transferred data")
