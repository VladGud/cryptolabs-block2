from ca import User, CertificationAuthority
from crypto_primitives import  derive_aes_keys, encrypt_with_aes, decrypt_with_aes, DiffieHellmanParty

from Crypto.Random import get_random_bytes, random

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Router(User):
    def __init__(self, ca, name, diffie_prime, diffie_generator, next_node):
        super().__init__(name, ca)

        self.diffie = DiffieHellmanParty(diffie_prime, diffie_generator)
        self.next_node = next_node
        self.init_connection = False

    def establish_connection(self, ephemeral_dh_pub_key):
        shared_secret_key = self.diffie.generate_shared_secret(ephemeral_dh_pub_key)
        self.encryption_key = derive_aes_keys(shared_secret_key, b"")

    def set_connection(self, ciphertext):
        ephemeral_dh_pub_key_str = self.decrypt_data(ciphertext)
        ephemeral_dh_pub_key = int.from_bytes(ephemeral_dh_pub_key_str, byteorder='big')
        self.establish_connection(ephemeral_dh_pub_key)
        self.init_connection = True
        ephemeral_dh_pub_key = self.diffie.get_public_key()
        return ephemeral_dh_pub_key.to_bytes((ephemeral_dh_pub_key.bit_length() + 7) // 8, byteorder='big')

    def get_message_and_proxy(self, ciphertext):
        if not self.init_connection:
            return self.set_connection(ciphertext)

        decrypted_text = decrypt_with_aes(ciphertext, self.encryption_key)
        message = self.next_node.get_message_and_proxy(decrypted_text)
        return encrypt_with_aes(message, self.encryption_key) 


class Site(Router):
    def __init__(self, ca, name, diffie_prime, diffie_generator, next_node):
        super().__init__(ca, name, diffie_prime, diffie_generator, next_node)

    def get_message_and_proxy(self, ciphertext):
        if not self.init_connection:
            return self.set_connection(ciphertext)

        client_message = decrypt_with_aes(ciphertext, self.encryption_key)
        print("Site get:", client_message)

        message = b"Response 200"
        return encrypt_with_aes(message, self.encryption_key) 


class TorClient(): 
    def __init__(self, diffie, node_certificates, first_node):
        self.node_certificates = node_certificates
        self.first_node = first_node
        self.diffie = diffie
        
    def encrypt_message(self, message):
        for key in self.node_keys:
            message = encrypt_with_aes(message, key)

        return message

    def decrypt_message(self, encrypted_message):
        for key in reversed(self.node_keys):
            encrypted_message = decrypt_with_aes(encrypted_message, key)

        return encrypted_message

    def get_params_for_init_connection(self, node_certificate):
        ephemeral_dh_pub_key = self.diffie.get_public_key()
        plaintext = ephemeral_dh_pub_key.to_bytes((ephemeral_dh_pub_key.bit_length() + 7) // 8, byteorder='big')
        ciphertext = node_certificate.public_key().encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.encrypt_message(ciphertext)


    def establish_connection(self):
        self.node_keys = []
        for node_certificate in self.node_certificates:
            encrypted_params = self.get_params_for_init_connection(node_certificate)
            encrypted_ephemeral_dh_router_pk = self.first_node.get_message_and_proxy(encrypted_params)
            ephemeral_dh_router_pk_str = self.decrypt_message(encrypted_ephemeral_dh_router_pk)
            ephemeral_dh_router_pk = int.from_bytes(ephemeral_dh_router_pk_str, byteorder='big')
            shared_secret_key = self.diffie.generate_shared_secret(ephemeral_dh_router_pk)
            self.node_keys.insert(0, derive_aes_keys(shared_secret_key, b""))
            
            # Regenerate private key
            self.diffie.generate_private_key()

        return True

    def send_message(self, message):
        encrypted_message = self.encrypt_message(message)
        encrypted_result = self.first_node.get_message_and_proxy(encrypted_message)
        result = self.decrypt_message(encrypted_result)
        print("Client get result:", result)
        return result

def main():
    ca = CertificationAuthority()
    diffie = DiffieHellmanParty()

    site = Site(ca, "Site github", diffie.get_group(), diffie.get_generator(), None)
    print("\nGenerate Site certificate...")
    if site.generate_certificate_signing():
        print("Success Site generate_certificate_signing")
    else:
        print("Failed Site generate_certificate_signing")
        return

    or2 = Router(ca, "SecondRouter", diffie.get_group(), diffie.get_generator(), site)
    print("\nGenerate Router2 certificate...")
    if or2.generate_certificate_signing():
        print("Success Router2 generate_certificate_signing")
    else:
        print("Failed Router2 generate_certificate_signing")
        return

    or1 = Router(ca, "FirstRouter", diffie.get_group(), diffie.get_generator(), or2)
    print("\nGenerate Router1 certificate...")
    if or1.generate_certificate_signing():
        print("Success Router1 generate_certificate_signing")
    else:
        print("Failed Router1 generate_certificate_signing")
        return

    client = TorClient(diffie, [or1.get_certificate(), or2.get_certificate(), site.get_certificate()], or1)
    print("\nEstablish connection to Tor network...")
    if client.establish_connection():
        print("Success create connection")
    else:
        print("Failed create connection")
        return

    client.send_message(b"Hello world!")


    print('Negative case:')
    # print("Invalid site shared key")
    # site.encryption_key = get_random_bytes(32)
    # client.send_message(b"Hello world!")

    print("Invalid Router2 shared key")
    or2.encryption_key = get_random_bytes(32)
    client.send_message(b"Hello world!")

if __name__ == '__main__':
    main()