# Offline Node
# Bruce Englert, Meghana Gupta, Ray Grant
import pickle
import socket
import Functions
import Modified_SSL_Handshake

private_key = Functions.generate_private_key()


# def handle_middle_node_connection(middle_node_socket, address):
#     [good_handshake, middle_node_public] = Modified_SSL_Handshake.server_ssl_handshake(middle_node_socket, "Offline Node", private_key)
#     if good_handshake:
#         handle_DH_exchange(middle_node_socket)
#     else:
#         print("handshake failed")


# def data_transfer(middle_node_socket):
#     pass


def handle_DH_exchange():
    middle_socket = Modified_SSL_Handshake.handle_node_connection(5433)

    # DIP - 4
    dh_msg = Functions.read_message_with_delimiter(middle_socket)
    online_dh_public = Functions.load_der_public_key(dh_msg["dh_public_through"], Modified_SSL_Handshake.default_backend())

    # DIP - 5
    private_dh_key = Modified_SSL_Handshake.gen_priv_dh_send_pub_dh(middle_socket, "Offline Node", private_key)

    return Functions.generate_dh_shared_key(private_dh_key, online_dh_public.public_numbers().y)


def handle_transferred_data(shared_key):
    middle_socket = Modified_SSL_Handshake.handle_node_connection(5433) # TODO: might need to change port

    transfer_msg = Functions.read_message_with_delimiter(middle_socket)
    decrypted_data = Functions.aes_decrypt(transfer_msg["iv"], shared_key, transfer_msg["encrypted_data"])

    data_array = pickle.loads(decrypted_data)

    print(transfer_msg)
    print(data_array)
    # TODO: return the actual data.


# def start_data_transfer_phase():
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((socket.gethostname(), 5434))
#     s.listen()
#     second_connection, address = s.accept()
#     handle_transferred_data(second_connection)


shared_dh = handle_DH_exchange()
print("[Offline Node] Established DH: ", shared_dh)
handle_transferred_data(shared_dh)
print("[Offline Node] Accepted Transferred Data")
# start of program
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.bind((socket.gethostname(), 5433))
# s.listen()
#
# middle_node_socket, address = s.accept()
# print(f"Connection from {address}")
# handle_middle_node_connection(middle_node_socket, address)
# start_data_transfer_phase()
