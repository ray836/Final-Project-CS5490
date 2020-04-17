from Functions import *


# --------------------- Modified SSL Handshake -----------------------
def server_ssl_handshake(node_socket, node_name, private_key):
    all_msgs = ""

    # ---- msg 1
    received_msg1 = read_message_with_delimiter(node_socket)
    all_msgs += str(received_msg1)
    print(f"[{node_name}] Received: ", str(received_msg1))

    # determine encryption/integrity algorithms
    if "AES" in received_msg1["supported_data_encryption_algs"]:
        print(f"[{node_name}] Chosen Encryption is AES")
    else:
        print(f"[{node_name}] Unsupported data encryption algs")
        node_socket.close()
        return False
    if "AES" in received_msg1["supported_integrity_algs"]:
        print(f"[{node_name}] Chosen Integrity protection is AES")
    else:
        print(f"[{node_name}] Unsupported integrity algs")
        node_socket.close()
        return False

    online_node_certificate = loadCert(received_msg1["certificate"])
    online_node_public_key = online_node_certificate.public_key()

    # verify signature
    try:
        verifyCertificateSignature(online_node_certificate, online_node_public_key)
    except cryptography.exceptions.InvalidSignature:
        print(f"[{node_name}] Signaturew was not valid.")
        node_socket.close()
        return False

    # create certificate
    cert = createCertificate(private_key)
    # ---- msg 2
    msg2 = {"certificate": certificate_to_byes(cert),
            "chosen_data_encryption_alg": "AES",
            "chosen_integrity_alg": "AES"}
    all_msgs += str(msg2)
    print(f"[{node_name}] Sending: ", msg2)
    node_socket.sendall(wrap_to_send(msg2))

    print(f"First part of Handshake Working!")

    # ----- Diffie Hellman ---------
    # ---- msg 3
    msg3 = read_message_with_delimiter(node_socket)
    all_msgs += str(msg3)
    print(f"[{node_name}] Received: ", msg3)
    client_dh_public_key = load_der_public_key(msg3["dh_public"], default_backend())
    print(f"[{node_name}] Diffie Hellman public key received: ", client_dh_public_key)
    signed_client_dh_public_key = msg3["signed_dh_public"]

    # Verify dh signed value
    try:
        rsa_signature_verification(online_node_public_key, signed_client_dh_public_key, msg3["dh_public"])
    except Exception:
        print("Signed Diffie Hellman was not verified")
        node_socket.close()
        return False

    # generate DH keys
    [dh_private_key, dh_public_key] = generate_dh_private_public_key()
    print(f"[{node_name}] Generated Diffie Hellman Public Key: ", dh_public_key)
    msg4 = {"dh_public": dh_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), "signed_dh_public": rsa_private_sign(private_key, dh_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))}
    print(f"[{node_name}] Sending: ", msg4)
    all_msgs += str(msg4)
    node_socket.sendall(wrap_to_send(msg4))


    shared_k = generate_dh_shared_key(dh_private_key, client_dh_public_key.public_numbers().y)
    print(f"[{node_name}] shared key: ", shared_k)

    # Generate MAC
    created_MAC = create_MAC(all_msgs)
    [iv, encrypted_mac] = aes_encrypt(shared_k, created_MAC)
    msg3_5 = {"iv": iv, "encrypted_mac": encrypted_mac}

    all_msgs += str(msg3_5)
    print(f"[{node_name}] Sending: ", str(msg3_5))
    node_socket.sendall(wrap_to_send(msg3_5))

    # Receive MAC
    msg4 = read_message_with_delimiter(node_socket)
    print(f"[{node_name}] Received: ", str(msg4))
    all_msgs_before_mac = all_msgs
    all_msgs += str(msg4)
    encrypted_online_node_mac = msg4["encrypted_mac"]
    decrypted_online_node_mac = aes_decrypt(msg4["iv"], shared_k, encrypted_online_node_mac)

    # verify MAC
    if valid_mac(all_msgs_before_mac, decrypted_online_node_mac):
        print(f"[{node_name}] MAC is Valid")
    else:
        print(f"[{node_name}] MAC was not validated.")
        node_socket.close()
        return False

    return True


def client_ssl_handshake(node_socket, node_name, private_key):
    all_msgs = ""

    # ---- msg 1
    supported_data_encryption_algs = ["AES"]
    supported_integrity_algs = ["AES"]

    cert = createCertificate(private_key)

    msg1 = {"certificate": certificate_to_byes(cert),
            "supported_data_encryption_algs": supported_data_encryption_algs,
            "supported_integrity_algs": supported_integrity_algs}

    all_msgs += str(msg1)
    print("[Online Node] Sending: ", msg1)
    node_socket.sendall(wrap_to_send(msg1))

    # ---- msg 2
    received_msg2 = read_message_with_delimiter(node_socket)
    print("[Online Node] Received: ", str(received_msg2))
    all_msgs += str(received_msg2)

    middle_node_certificate = loadCert(received_msg2["certificate"])
    middle_node_public_key = middle_node_certificate.public_key()

    # verify certificate
    print("[Online Node] Verifying Certificate... ", end="")
    try:
        verifyCertificateSignature(middle_node_certificate, middle_node_public_key)
    except cryptography.exceptions.InvalidSignature:
        print("Verification Failed!")
        node_socket.close()
        return False

    # generate DH keys
    [dh_private_key, dh_public_key] = generate_dh_private_public_key()

    msg4 = {"dh_public": dh_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
            "signed_dh_public": rsa_private_sign(private_key, dh_public_key.public_bytes(Encoding.DER,
                                                                                         PublicFormat.SubjectPublicKeyInfo))}
    print(f"[{node_name}] Sending: ", msg4)
    all_msgs += str(msg4)
    node_socket.sendall(wrap_to_send(msg4))

    msg30 = read_message_with_delimiter(node_socket)
    all_msgs += str(msg30)

    client_dh_public_key = load_der_public_key(msg30["dh_public"], default_backend())
    signed_client_dh_public_key = msg30["signed_dh_public"]

    # Verify dh signed value
    try:
        rsa_signature_verification(middle_node_public_key, signed_client_dh_public_key, msg30["dh_public"])
    except Exception:
        print("Signed Diffie Hellman was not verified")
        node_socket.close()
        return False

    shared_k = generate_dh_shared_key(dh_private_key, client_dh_public_key.public_numbers().y)
    print(f"[{node_name}]shared key: ", shared_k)

    # Receive MAC
    msg4 = read_message_with_delimiter(node_socket)
    print("[Middle Node] Received: ", str(msg4))
    all_msgs_before_mac = all_msgs
    all_msgs += str(msg4)
    encrypted_online_node_mac = msg4["encrypted_mac"]
    decrypted_online_node_mac = aes_decrypt(msg4["iv"], shared_k, encrypted_online_node_mac)

    # verify MAC
    if valid_mac(all_msgs_before_mac, decrypted_online_node_mac):
        print("[Middle Node] MAC is Valid")
    else:
        print("[Middle Node] MAC was not validated.")
        node_socket.close()
        return False

    # Generate MAC
    created_MAC = create_MAC(all_msgs)
    [iv, encrypted_mac] = aes_encrypt(shared_k, created_MAC)
    msg3_5 = {"iv": iv, "encrypted_mac": encrypted_mac}

    all_msgs_before_mac = all_msgs
    all_msgs += str(msg3_5)
    print("[Middle Node] Sending: ", str(msg3_5))
    node_socket.sendall(wrap_to_send(msg3_5))

    node_socket.close()
    return True
