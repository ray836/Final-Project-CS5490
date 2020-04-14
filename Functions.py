# Common Functions
# Bruce Englert, Meghana Gupta, Ray Grant

# This file will store functions that are used between the nodes.
import pickle
import datetime
import operator
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import serialization


# --------- Socket/Transmission Helper Functions -----
def read_message_with_delimiter(given_socket):
    full_msg = b''
    delimiter = b'\n\n'
    done_reading = False
    msg = b''
    while not done_reading:
        msg = given_socket.recv(1024)
        done_reading = delimiter in msg
        if done_reading:
            msg = msg[0:-2]
        if len(msg) > 0:
            full_msg += msg
            if done_reading:
                return pickle.loads(full_msg)

    return pickle.loads(full_msg)


def wrap_to_send(inner_python_dictionary):
    return pickle.dumps(inner_python_dictionary) + b'\n\n'


# ---------- Functions needed for SSL ---------
def generate_private_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key


def createCertificate(key):
    # create certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Utah"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Salt Lake City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False
    ).sign(key, hashes.SHA256(), default_backend())

    return cert


# Loads a certificate object from PEM_bytes
def loadCert(PEM_bytes):
    cert = x509.load_pem_x509_certificate(PEM_bytes, default_backend())
    return cert


def certificate_to_byes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def verifyCertificateSignature(cert_to_check, issuer_public_key):
    # This will throw an error if verify fails
    issuer_public_key.verify(
        cert_to_check.signature,
        cert_to_check.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert_to_check.signature_hash_algorithm,
    )
    print("Verification Successful")


def get_master_key(n1, n2):
    return bytes(map(operator.xor, n1, n2))


def rsa_public_encrypt(public_key, msg_in_bytes):
    ciphertext = public_key.encrypt(
        msg_in_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_private_decrypt(private_key, ciphertext):
    decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_text


# ---- Key Generation ----
def get_SHA_1_Hash(input_bytes):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input_bytes)
    return digest.finalize()


def generate4keys(master_key):
    master_key_len = len(master_key)
    key_mask_1 = b''
    key_mask_2 = b''
    key_mask_3 = b''
    for i in range(0, master_key_len):
        key_mask_1 += b'1'
        key_mask_2 += b'0'
        key_mask_3 += b'2'
    key_input1 = bytes(map(operator.xor, master_key, key_mask_1))
    key_input2 = bytes(map(operator.xor, master_key, key_mask_2))
    key_input3 = bytes(map(operator.xor, master_key, key_mask_3))

    return [get_SHA_1_Hash(key_input1),
            get_SHA_1_Hash(key_input2),
            get_SHA_1_Hash(key_input3),
            get_SHA_1_Hash(master_key)]


# --------- Data Transfer Phase ----------------
def aes_encrypt(key, byte_data):
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(byte_data)
    padded_data += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return [iv, cipher_text]


def aes_decrypt(iv, key, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(byte_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_bytes)
    unpadded_data = data + unpadder.finalize()
    return unpadded_data