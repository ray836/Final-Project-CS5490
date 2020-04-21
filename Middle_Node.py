# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant

import Functions
import Modified_SSL_Handshake

# DIP - Delayed Intermediate Protocol

private_key = Functions.generate_private_key()
ONLINE_PORT = 5432
OFFLINE_PORT = 5433
online_shared_key = b''
offline_shared_key = b''


def perform_online_handshake(online_node_socket, address):
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


def handle_DH_online_connection():
    online_socket = Modified_SSL_Handshake.handle_node_connection(5432)

    given_dh_value = Functions.read_message_with_delimiter(online_socket)
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


def initiate_DH_online_connection(node_2_public_dh):
    online_socket = Modified_SSL_Handshake.connect_to_node(5432)

    # send offline DH
    online_socket.sendall(Functions.wrap_to_send(node_2_public_dh))

    # Receive transfer data
    data_to_transfer = Functions.read_message_with_delimiter(online_socket)
    online_socket.close()
    return data_to_transfer


def transfer_data(data):
    offline_socket = Modified_SSL_Handshake.connect_to_node(5433)
    offline_socket.send(Functions.wrap_to_send(data))
    offline_socket.close()


def main():
    online_dh_value = handle_DH_online_connection()
    print("[Middle Node] Received online dh part")
    offline_dh_value = initiate_DH_offline_connection(online_dh_value)
    print("[Middle Node] Received offline dh part")
    data_to_transfer = initiate_DH_online_connection(offline_dh_value)
    print("[Middle Node] Transferring data...")
    transfer_data(data_to_transfer)

    # TODO: Integrate timing for additional data transferring.

if __name__ == '__main__':
    main()
