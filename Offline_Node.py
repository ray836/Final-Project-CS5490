# Offline Node
# Bruce Englert, Meghana Gupta, Ray Grant
import pickle
import time

import Functions
import Modified_SSL_Handshake

private_key = Functions.generate_private_key()


def handle_DH_exchange():
    middle_socket = Modified_SSL_Handshake.handle_node_connection(5433)

    dh_msg = Functions.read_message_with_delimiter(middle_socket)
    online_dh_public = Functions.load_der_public_key(dh_msg["dh_public_through"], Modified_SSL_Handshake.default_backend())
    private_dh_key = Modified_SSL_Handshake.gen_priv_dh_send_pub_dh(middle_socket, "Offline Node", private_key)
    middle_socket.close()
    return Functions.generate_dh_shared_key(private_dh_key, online_dh_public.public_numbers().y)


def handle_transferred_data(shared_key):
    middle_socket = Modified_SSL_Handshake.handle_node_connection(5433)  # TODO: might need to change port

    transfer_msg = Functions.read_message_with_delimiter(middle_socket)
    decrypted_data = Functions.aes_decrypt(transfer_msg["iv"], shared_key, transfer_msg["encrypted_data"])
    data_array = pickle.loads(decrypted_data)
    print(data_array)
    middle_socket.close()
    return data_array


shared_dh = handle_DH_exchange()
print("[Offline Node] Established DH: ", shared_dh)

for i in range(1, 10):
    time.sleep(6)
    print("handling transfered data...")
    handle_transferred_data(shared_dh)
    print("[Offline Node] Accepted Transferred Data")

