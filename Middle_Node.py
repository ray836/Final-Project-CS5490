# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant
import random
import time

import Functions
import Modified_SSL_Handshake
import MySQLdb


# DIP - Delayed Intermediate Protocol

private_key = Functions.generate_private_key()
ONLINE_PORT = 5432
OFFLINE_PORT = 5433
online_shared_key = b''
offline_shared_key = b''

online_n = random.randint(100, 200)
offline_n = random.randint(100, 200)

next_time = 0


def perform_online_handshake(online_node_socket):
    global online_shared_key
    [successful_handshake, computed_shared_key] = Modified_SSL_Handshake.server_ssl_handshake(online_node_socket,
                                                                                              "Middle Node",
                                                                                              private_key)
    online_shared_key = computed_shared_key

    return successful_handshake


def perform_offline_handshake(online_node_socket):
    global offline_shared_key
    [successful_handshake, shared_k] = Modified_SSL_Handshake.client_ssl_handshake(online_node_socket, "Middle Node",
                                                                                   private_key)
    offline_shared_key = shared_k
    return successful_handshake


def send_n(node_socket):
    global online_n
    online_n = random.randint(100, 200)
    print("[Middle Node] Sending authorization n.", online_n)
    [iv, encrypted_n] = Functions.aes_encrypt(online_shared_key, bytes([online_n]))
    n_msg = {"n": {"iv": iv, "encrypted_n": encrypted_n}}
    node_socket.sendall(Functions.wrap_to_send(n_msg))


def send_next_time(node_socket):
    global next_time
    next_time = random.randint(5, 20)
    [iv, encrypted_time] = Functions.aes_encrypt(online_shared_key, bytes([next_time]))
    next_t_msg = {"next_time": {"iv": iv, "encrypted_time": encrypted_time}}
    print("[Middle Node] Sending next time", next_time)
    node_socket.sendall(Functions.wrap_to_send(next_t_msg))


def handle_DH_1_online_connection():
    global online_shared_key

    online_socket = Modified_SSL_Handshake.handle_node_connection(5432)
    perform_online_handshake(online_socket) # TODO check if returns true

    given_dh_value = Functions.read_message_with_delimiter(online_socket)

    # send encrypted n
    send_n(online_socket)
    send_next_time(online_socket)
    online_socket.close()
    return given_dh_value


def receive_data_transfer(node_socket):
    return Functions.read_message_with_delimiter(node_socket)


def initiate_DH_offline_connection(node_1_public_dh):
    offline_socket = Modified_SSL_Handshake.connect_to_node(5433)

    # send online DH
    offline_socket.sendall(Functions.wrap_to_send(node_1_public_dh))

    node_3_dh = Functions.read_message_with_delimiter(offline_socket)
    offline_socket.close()
    return node_3_dh


def sanitize_data(data_string):
    return MySQLdb.escape_string(data_string).decode()


def receive_verify_online_n(node_socket):
    global online_n

    n_msg = Functions.read_message_with_delimiter(node_socket)
    decrypted_n_bytes = Functions.aes_decrypt(n_msg["n"]["iv"], online_shared_key, n_msg["n"]["encrypted_n"])
    decrypted_n = int.from_bytes(decrypted_n_bytes, byteorder='big')

    if decrypted_n == online_n-1:
        print("[Middle Node] n was received and verified")
    else:
        print("[Middle Node] given n failed authorization test", online_n)
        print("should be: ", decrypted_n)
        node_socket.close()


def handle_DH_2_online_connection(node_2_public_dh):
    print("opening online connection...")
    online_socket = Modified_SSL_Handshake.handle_node_connection(5432)

    # receive n-1
    receive_verify_online_n(online_socket)

    # send offline DH
    online_socket.sendall(Functions.wrap_to_send(node_2_public_dh))
    print("[Middle Node] sent DH")

    send_n(online_socket)
    time.sleep(2)
    send_next_time(online_socket)

    online_socket.close()


def transfer_data(data):
    offline_socket = Modified_SSL_Handshake.connect_to_node(5433)
    offline_socket.send(Functions.wrap_to_send(data))
    offline_socket.close()


def receive_transfer_data():
    online_socket = Modified_SSL_Handshake.handle_node_connection(5432)

    receive_verify_online_n(online_socket)
    data_to_transfer = Functions.read_message_with_delimiter(online_socket)

    send_n(online_socket)
    time.sleep(2)
    send_next_time(online_socket)
    print("received data")
    online_socket.close()
    return data_to_transfer


def main():
    online_dh_value = handle_DH_1_online_connection()
    print("[Middle Node] Received online dh part")
    offline_dh_value = initiate_DH_offline_connection(online_dh_value)
    print("[Middle Node] Received offline dh part")
    time.sleep(next_time-5)
    handle_DH_2_online_connection(offline_dh_value)
    print("[Middle Node] Transferring data...")

    for i in range(1, 10):
        print("sleeping...", next_time)
        time.sleep(next_time - 1)
        print("sending data to transfer")
        data_to_transfer = receive_transfer_data()
        transfer_data(data_to_transfer)


if __name__ == '__main__':
    main()

