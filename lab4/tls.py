from ca import User, CertificationAuthority
from crypto_primitives import  derive_aes_keys, encrypt_with_aes, decrypt_with_aes, generate_mac_with_aes, DiffieHellmanParty, EllipticCurveDiffieHellmanParty

from Crypto.Random import get_random_bytes, random

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def is_correct_diffie_type(cipher_suite):
    match cipher_suite:
        case "curve":
            return EllipticCurveDiffieHellmanParty
        case "default":
            return DiffieHellmanParty
        case _:
            raise ValueError("Incorrect cipher_suite")

def get_diffie_type(cipher_suite):
    match cipher_suite:
        case "curve":
            return EllipticCurveDiffieHellmanParty
        case "default":
            return DiffieHellmanParty
        case _:
            raise ValueError("Incorrect cipher_suite")

class TLSClient(User):
    """
    Клиент для TLS 1.3
    """ 
    
    def __init__(self, ca, name, cipher_suite):
        """
        Инициализация - разбор набора примитивов
        """
        
        super().__init__(ca, name)
        self.cipher_suite = cipher_suite
        self.diffie_type = get_diffie_type(cipher_suite)
        self.session_keys = {}

        self.SERVER_KEY = 0
        self.CLIENT_KEY = 1
        
        
    def establish_connection(self, server, auth_mode):
        """
        Установление соединения с сервером
        """
        
        diffie = self.diffie_type()
        
        ephemeral_dh_pk = diffie.get_public_key()
        client_nonce    = get_random_bytes(64)
        
        offer = (self.cipher_suite, diffie.get_group(), diffie.get_generator())
        
        is_one_way = auth_mode == "OWA"
        server_hello = server.get_hello(self.name, ephemeral_dh_pk, client_nonce, 
                                        offer, is_one_way)
        
        if server_hello is None:
            raise RuntimeError("Server unreachable")
        
        ephemeral_dh_server_pub_key, server_nonce, cipher_suite, c1, c2, c3, c4 = server_hello
        
        if cipher_suite != self.cipher_suite:
            raise RuntimeError(f'Unsupported cipher suite {cipher_suite}')
        
        shared_secret_key = diffie.generate_shared_secret(ephemeral_dh_server_pub_key)

        encryption_key = derive_aes_keys(shared_secret_key, server_nonce + client_nonce)
        
        cert_requested = decrypt_with_aes(*c1, encryption_key)
        server_certificate_bytes = decrypt_with_aes(*c2, encryption_key)
        server_certificate = x509.load_pem_x509_certificate(server_certificate_bytes, default_backend())
        server_signature = decrypt_with_aes(*c3, encryption_key)
        server_mac = decrypt_with_aes(*c4, encryption_key)
        
        if not self.verify_data(client_nonce, server_signature, server_certificate):
            raise RuntimeError('Invalid verify server')
        
        if not is_one_way:
            c5 = encrypt_with_aes(self.certificate.public_bytes(encoding=serialization.Encoding.PEM), encryption_key)
            
            signature = self.sign_data(server_nonce)
            c6 = encrypt_with_aes(signature, encryption_key)
            
            mac = generate_mac_with_aes(server_nonce, encryption_key)
            c7 = encrypt_with_aes(mac, encryption_key)
        
            # generate raise in negative case
            server.process_client_certificate(self.name, c5, c6, c7)
        
        server_key = derive_aes_keys(shared_secret_key, client_nonce)
        client_key = derive_aes_keys(shared_secret_key, server_nonce)

        self.session_keys[server.name] = (server_key, client_key)
        
        print('The established connection')
        return True
    
    
    def send_wait_receive_message(self, server, message: str):
        """
        Отправка сообщения на сервер и получение ответа
        """
        if server.name not in self.session_keys:
            raise ValueError(f'Connection with server {server.name} is not established yet')

        encrypted_message = encrypt_with_aes(message.encode(), self.session_keys[server.name][self.CLIENT_KEY])
        
        response = server._receive_message_and_respond(self.name, encrypted_message)
        if response is None:
            raise RuntimeError("Server unreachable")
        

        message_from_server = decrypt_with_aes(*response, self.session_keys[server.name][self.SERVER_KEY])
        return message_from_server
            
            
    def change_keys(self, server):
        """
        Смена ключей по инициативе клиента
        """
        
        if server.name not in self.session_keys:
            raise ValueError(f'Connection with server {server.name} is not established yet')
        
        
        self.session_keys[server.name] = (
            derive_aes_keys(self.session_keys[server.name][self.SERVER_KEY], b""), 
            derive_aes_keys(self.session_keys[server.name][self.CLIENT_KEY], b"")
        )

        server.change_keys_by_client(self.name)

    def change_keys_by_server(self, server_id):
        self.session_keys[server_id] = (
            derive_aes_keys(self.session_keys[server_id][self.SERVER_KEY], b""), 
            derive_aes_keys(self.session_keys[server_id][self.CLIENT_KEY], b"")
        )


class TLSServer(User):    
    def __init__(self, ca, name, supported_cipher_suites):
        """
        Инициализация - сохранение настроек
        """
        
        super().__init__(ca, name)

        for cipher_suite in supported_cipher_suites:
            is_correct_diffie_type(cipher_suite)

        self.supported_cipher_suites = supported_cipher_suites
        self.session_keys  = {}
        self._mapped_states = {}

        self.SERVER_KEY = 0
        self.CLIENT_KEY = 1
        
        
    def get_hello(self, client_id, ephemeral_dh_client_pk, client_nonce, offer, is_one_way):
        """
        Получение ServerHello
        """
        
        cipher_suite, group, generator = offer
        
        if cipher_suite not in self.supported_cipher_suites:
            raise RuntimeError(f'Unsupported cipher suite {cipher_suite}')
        
        diffie_type = get_diffie_type(cipher_suite)
        
        diffie = diffie_type(group, generator) 

        ephemeral_dh_pk = diffie.get_public_key()
        server_nonce    = get_random_bytes(64)
        
        shared_secret_key = diffie.generate_shared_secret(ephemeral_dh_client_pk)
        
        encryption_key = derive_aes_keys(shared_secret_key, server_nonce + client_nonce)

        c1 = encrypt_with_aes(bytes([is_one_way]), encryption_key)
        c2 = encrypt_with_aes(self.certificate.public_bytes(encoding=serialization.Encoding.PEM), encryption_key)
        
        signature = self.sign_data(client_nonce)
        c3 = encrypt_with_aes(signature, encryption_key)
        
        mac = generate_mac_with_aes(client_nonce, encryption_key)
        c4 = encrypt_with_aes(mac, encryption_key)
        
        self._mapped_states[client_id] = [None, None, None, None, None, None]

        if is_one_way:
            server_key = derive_aes_keys(shared_secret_key, client_nonce)
            client_key = derive_aes_keys(shared_secret_key, server_nonce)
            self.session_keys[client_id] = (server_key, client_key)

        self._mapped_states[client_id]  = (server_nonce, client_nonce, cipher_suite, shared_secret_key)
        
        return ephemeral_dh_pk, server_nonce, cipher_suite, c1, c2, c3, c4

    def process_client_certificate(self, client_id, c5, c6, c7):     
        server_nonce, client_nonce, cipher_suite, shared_secret_key = self._mapped_states[client_id]
        encryption_key = derive_aes_keys(shared_secret_key, server_nonce + client_nonce)

        client_certificate_bytes = decrypt_with_aes(*c5, encryption_key)
        client_certificate = x509.load_pem_x509_certificate(client_certificate_bytes, default_backend())
        client_signature = decrypt_with_aes(*c6, encryption_key)
        client_mac = decrypt_with_aes(*c7, encryption_key)

        if not self.verify_data(server_nonce, client_signature, client_certificate):
            raise RuntimeError('Invalid verify server')
        
        server_key = derive_aes_keys(shared_secret_key, client_nonce)
        client_key = derive_aes_keys(shared_secret_key, server_nonce)
        self.session_keys[client_id] = (server_key, client_key)
        
        return True

    def change_keys(self, client):
        """
        Смена ключей по инициативе клиента
        """
        
        if client.name not in self.session_keys:
            raise ValueError(f'Connection with server {client.name} is not established yet')
        
        
        self.session_keys[client.name] = (
            derive_aes_keys(self.session_keys[client.name][self.SERVER_KEY], b""), 
            derive_aes_keys(self.session_keys[client.name][self.CLIENT_KEY], b"")
        )

        client.change_keys_by_server(self.name)

    def change_keys_by_client(self, client_id):
        self.session_keys[client_id] = (
            derive_aes_keys(self.session_keys[client_id][self.SERVER_KEY], b""), 
            derive_aes_keys(self.session_keys[client_id][self.CLIENT_KEY], b"")
        )

    def _receive_message_and_respond(self, client_id, encrypted_message):  
        message = decrypt_with_aes(*encrypted_message, self.session_keys[client_id][self.CLIENT_KEY]).decode()
        print(f'Received message "{message}"')

        return encrypt_with_aes(f'Hello, {message}!'.encode(), self.session_keys[client_id][self.SERVER_KEY])


def main():
    ca = CertificationAuthority()
    alice = TLSClient("Alice", ca, "default")
    bob = TLSClient("Bob", ca, "curve")

    server = TLSServer("Server", ca, ["default", "curve"])

    print("Success init CA, Bob and Alice")

    print("\nGenerate Alice certificate...")
    if alice.generate_certificate_signing():
        print("Success Alice generate_certificate_signing")
    else:
        print("Failed Alice generate_certificate_signing")
        return

    print("\nGenerate Bob certificate...")
    if bob.generate_certificate_signing():
        print("Success Bob generate_certificate_signing")
    else:
        print("Failed Bob generate_certificate_signing")
        return

    print("\nGenerate Server certificate...")
    if server.generate_certificate_signing():
        print("Success Server generate_certificate_signing")
    else:
        print("Failed Server generate_certificate_signing")
        return

    print("\nAlice(OWA) is connecting to Server...")
    if not alice.establish_connection(server, "OWA"):
        print("Error: Alice can't create established connection")

    alice.send_wait_receive_message(server, "Alice test message")

    print("\nBob(TWA) is connecting to Server...")
    if not alice.establish_connection(server, "TWA"):
        print("Error: Bob can't create established connection")

    alice.send_wait_receive_message(server, "Bob test message")


    print('Negative case:')
    # server_with_unsupported_suite = TLSServer("server with unsupported cipher_suite", ca, ["curve"])
    # print("\nGenerate Server certificate...")
    # if server_with_unsupported_suite.generate_certificate_signing():
    #     print("Success Server generate_certificate_signing")
    # else:
    #     print("Failed Server generate_certificate_signing")
    #     return
    # alice.establish_connection(server_with_unsupported_suite, "TWA")

    server_with_unsupported_suite = TLSServer("server with unsupported cipher_suite", ca, ["kkk"])

if __name__ == '__main__':
    main()