import base64
import os
import datetime
from datetime import timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import logging

# Setup logging for audit trail
logging.basicConfig(filename='contract_exchange.log', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# Simulated Certificate Authority for key pair generation and certificate issuance
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_self_signed_cert(private_key, public_key, subject):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365))
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    return certificate

# Simulate secure TLS channel
def send(sender, receiver, message):
    logging.info(f"{sender} sends to {receiver}: {message}")
    print(f"{sender} sends to {receiver}: {message}")
    return message

# Hash the contract
def hash_contract(contract):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(contract.encode())
    return digest.finalize().hex()

# Sign a message
def sign(private_key, message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    hash_value = digest.finalize()
    signature = private_key.sign(hash_value, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()

# Verify a signature
def verify(public_key, message, signature):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    hash_value = digest.finalize()
    try:
        public_key.verify(base64.b64decode(signature), hash_value, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# Protocol Implementation
def main():
    # Initialize parties and keys
    seller_solicitor_private, seller_solicitor_public = generate_key_pair()  # Seller's Solicitor
    facey_private, facey_public = generate_key_pair()  # Mr. L.M. Facey
    hnr_private, hnr_public = generate_key_pair()  # Hackit & Run LLP
    harvey_private, harvey_public = generate_key_pair()  # Mrs. Harvey

    # Generate certificates (simplified PKI)
    seller_solicitor_cert = generate_self_signed_cert(seller_solicitor_private, seller_solicitor_public, "Seller's Solicitor")
    facey_cert = generate_self_signed_cert(facey_private, facey_public, "Mr. L.M. Facey")
    hnr_cert = generate_self_signed_cert(hnr_private, hnr_public, "Hackit & Run LLP")
    harvey_cert = generate_self_signed_cert(harvey_private, harvey_public, "Mrs. Harvey")

    # Simulate prior communication (cached certificates for H&R and Seller's Solicitor)
    cached_certs = {
        "Hackit & Run LLP": hnr_cert.public_key(),
        "Seller's Solicitor": seller_solicitor_cert.public_key()
    }

    # Contract
    contract = "Property Sale Contract: Land at 123 Example St, London, UK"
    contract_hash = hash_contract(contract)
    logging.info(f"Contract hash: {contract_hash}")

    # Step 1: Seller's Solicitor sends contract to Mr. L.M. Facey
    send("Seller's Solicitor", "Mr. L.M. Facey", contract)

    # Step 2: Mr. L.M. Facey signs
    sig_facey = sign(facey_private, contract)
    send("Mr. L.M. Facey", "Seller's Solicitor", sig_facey)

    # Step 3: Seller's Solicitor verifies
    if not verify(facey_cert.public_key(), contract, sig_facey):
        logging.error("Verification failed at Seller's Solicitor")
        print("Verification failed at Seller's Solicitor")
        return

    # Step 4: Seller's Solicitor sends to Hackit & Run LLP
    message_to_hnr = (contract, sig_facey)
    send("Seller's Solicitor", "Hackit & Run LLP", message_to_hnr)

    # Step 5: Hackit & Run LLP verifies
    contract, sig_facey = message_to_hnr
    if not verify(facey_cert.public_key(), contract, sig_facey):
        logging.error("Verification failed at Hackit & Run LLP")
        print("Verification failed at Hackit & Run LLP")
        return

    # Step 6: Hackit & Run LLP sends to Mrs. Harvey
    message_to_harvey = (contract, sig_facey)
    send("Hackit & Run LLP", "Mrs. Harvey", message_to_harvey)

    # Step 7: Mrs. Harvey verifies and signs
    contract, sig_facey = message_to_harvey
    if not verify(facey_cert.public_key(), contract, sig_facey):
        logging.error("Verification failed at Mrs. Harvey")
        print("Verification failed at Mrs. Harvey")
        return
    sig_harvey = sign(harvey_private, contract)
    send("Mrs. Harvey", "Hackit & Run LLP", sig_harvey)

    # Step 8: Hackit & Run LLP verifies and sends to Seller's Solicitor
    if not verify(harvey_cert.public_key(), contract, sig_harvey):
        logging.error("Verification failed at Hackit & Run LLP")
        print("Verification failed at Hackit & Run LLP")
        return
    message_to_seller_solicitor = (contract, sig_harvey)
    send("Hackit & Run LLP", "Seller's Solicitor", message_to_seller_solicitor)

    # Step 9: Seller's Solicitor verifies
    contract, sig_harvey = message_to_seller_solicitor
    if not verify(harvey_cert.public_key(), contract, sig_harvey):
        logging.error("Verification failed at Seller's Solicitor")
        print("Verification failed at Seller's Solicitor")
        return

    print("Contract exchange completed successfully")
    logging.info("Contract exchange completed successfully")
    print(f"Seller's Solicitor holds: (Contract, Mrs. Harvey's Signature) = ({contract}, {sig_harvey})")
    print(f"Hackit & Run LLP holds: (Contract, Mr. L.M. Facey's Signature) = ({contract}, {sig_facey})")
    logging.info(f"Seller's Solicitor holds: (Contract, Mrs. Harvey's Signature) = ({contract}, {sig_harvey})")
    logging.info(f"Hackit & Run LLP holds: (Contract, Mr. L.M. Facey's Signature) = ({contract}, {sig_facey})")

if __name__ == "__main__":
    main()
