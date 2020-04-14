# Online Node
# Bruce Englert, Meghana Gupta, Ray Grant
# Final Project - Custom MCTLS Offline Server

import socket
import cryptography
import Functions

private_key = Functions.generate_private_key()

def connect_to_middle_node(middle_node_socket):
    ssl_handshake(middle_node_socket)
    data_transfer(middle_node_socket, "data")


def ssl_handshake(middle_node_socket):
    all_msgs = ""

    # ---- msg 1
    supported_data_encryption_algs = ["AES"]
    supported_integrity_algs = ["AES"]

    cert = Functions.createCertificate(private_key)

    msg1 = {"certificate": Functions.certificate_to_byes(cert),
            "supported_data_encryption_algs": supported_data_encryption_algs,
            "supported_integrity_algs": supported_integrity_algs}

    all_msgs += str(msg1)
    print("[Online Node] Sending: ", msg1)
    middle_node_socket.sendall(Functions.wrap_to_send(msg1))

    # ---- msg 2
    received_msg2 = Functions.read_message_with_delimiter(middle_node_socket)
    print("[Online Node] Received: ", str(received_msg2))
    all_msgs += str(received_msg2)

    middle_node_certificate = Functions.loadCert(received_msg2["certificate"])
    middle_node_public_key = middle_node_certificate.public_key()

    # verify certificate
    print("[Online Node] Verifying Certificate... ", end="")
    try:
        Functions.verifyCertificateSignature(middle_node_certificate, middle_node_public_key)
    except cryptography.exceptions.InvalidSignature:
        print("Verification Failed!")
        s.close()
        return

    print("Certificate Verification Complete!")
    s.close()


def data_transfer(middle_node_socket, data):
    pass


# start of program
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 5000))
connect_to_middle_node(s)
