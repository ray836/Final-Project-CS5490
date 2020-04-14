# Middle Node
# Bruce Englert, Meghana Gupta, Ray Grant

import socket
import cryptography
import Functions


def handle_online_node_connection(online_node_socket, address):
    ssl_handshake(online_node_socket)
    data_transfer(online_node_socket)


def ssl_handshake(node_socket):
    all_msgs = ""

    # ---- msg 1
    received_msg1 = Functions.read_message_with_delimiter(node_socket)
    all_msgs += str(received_msg1)
    print("[Middle Node] Received: ", str(received_msg1))

    # determine encryption/integrity algorithms

    if "AES" in received_msg1["supported_data_encryption_algs"]:
        print("[Middle Node] Chosen Encryption is AES")
    else:
        print("[Middle Node] Unsupported data encryption algs")
        node_socket.close()
        return
    if "AES" in received_msg1["supported_integrity_algs"]:
        print("[Middle Node] Chosen Integrity protection is AES")
    else:
        print("[Middle Node] Unsupported integrity algs")
        node_socket.close()
        return

    online_node_certificate = Functions.loadCert(received_msg1["certificate"])
    online_node_public_key = online_node_certificate.public_key()

    # verify signature
    try:
        Functions.verifyCertificateSignature(online_node_certificate, online_node_public_key)
    except cryptography.exceptions.InvalidSignature:
        print("[Middle Node] Signaturew was not valid.")
        node_socket.close()
        return

    # ---- msg 2
    msg2 = {"certificate": Functions.certificate_to_byes(online_node_certificate),
            "chosen_data_encryption_alg": "AES",
            "chosen_integrity_alg": "AES"}
    all_msgs += str(msg2)
    print("[Middle Node] Sending: ", msg2)
    node_socket.sendall(Functions.wrap_to_send(msg2))

    print("First part of Handshake Working!")
    node_socket.close()


def data_transfer(given_socket):
    pass


def main():
    # start of program
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), 5432))
    s.listen()

    while True:
        online_node_socket, address = s.accept()
        print(f"Connection from {address}")
        handle_online_node_connection(online_node_socket, address)


if __name__ == '__main__':
    main()
