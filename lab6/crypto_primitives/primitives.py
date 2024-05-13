from Crypto.Random import get_random_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


global_curve = ec.SECP256R1()
RANDOM_NONCE_LEN = 12

def encrypt_with_aes(plaintext, aes_key):
    """
    Шифрование текста с использованием ключа AES в режиме GCM
    """
    # Генерация случайного IV
    iv = get_random_bytes(16)
    
    # Инициализация шифра AES в режиме GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Шифрование текста
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Получение тэга аутентификации
    tag = encryptor.tag
    
    # Склейка iv, ciphertext и tag
    encrypted_data = iv + ciphertext + tag
    
    return encrypted_data

def decrypt_with_aes(encrypted_data, aes_key):
    """
    Дешифрование текста с использованием ключа AES в режиме GCM
    """
    # Разделение склееных данных на iv, ciphertext и tag
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    
    # Инициализация шифра AES в режиме GCM с заданным IV и тегом
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Расшифрование текста
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


def sha256(data):
    hash_algo = hashes.SHA256()
    digest = hashes.Hash(hash_algo)
    digest.update(data)
    hashed_data = digest.finalize()
    return bytes(hashed_data)


def derive_aes_keys(shared_secret, info):
    # Преобразование общего секрета в байтовую строку
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big') if type(shared_secret) != type(bytes()) \
                          else shared_secret

    # Создание объекта HKDF для первого ключа
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Длина ключа AES (256 бит)
        salt=None,
        info=info,
        backend=default_backend()
    )
    # Вычисление производного ключа для первого ключа
    aes_key = hkdf.derive(shared_secret_bytes)

    return aes_key


def box_gen_key():
    diffie = EllipticCurveDiffieHellmanParty(global_curve)
    return diffie.get_public_key(), diffie.get_private_key()


def box_encrypt(sender_sk, receiver_pk, kdf_context, cipher_context, meta, message):
    random_nonce = get_random_bytes(RANDOM_NONCE_LEN)

    diffie = EllipticCurveDiffieHellmanParty(global_curve, sender_sk) 
    shared_secret = diffie.generate_shared_secret(receiver_pk)

    shared_key = derive_aes_keys(shared_secret, kdf_context)

    d = sha256(cipher_context) + sha256(meta)

    cipher = ChaCha20Poly1305(shared_key)
    ciphertext = cipher.encrypt(random_nonce, message, associated_data=d)
    return random_nonce + ciphertext


def box_decrypt(receiver_sk, sender_pk, kdf_context, cipher_context, meta, ciphertext):
    random_nonce = ciphertext[:RANDOM_NONCE_LEN]
    ciphertext = ciphertext[RANDOM_NONCE_LEN:]

    diffie = EllipticCurveDiffieHellmanParty(global_curve, receiver_sk) 
    shared_secret = diffie.generate_shared_secret(sender_pk)

    shared_key = derive_aes_keys(shared_secret, kdf_context)

    d = sha256(cipher_context) + sha256(meta)

    cipher = ChaCha20Poly1305(shared_key)
    plaintext = cipher.decrypt(random_nonce, ciphertext, associated_data=d)
    return plaintext

class EllipticCurveDiffieHellmanParty:
    """
    Класс для участника протокола Диффи-Хеллмана на эллиптической кривой
    """

    def __init__(self, curve=None, private_key=None):
        self.curve = curve if curve is not None else ec.SECP256R1()
        if private_key is not None:
            self.private_key = private_key
        else:
            self.generate_private_key() 

    def set_private_key(self, private_key):
        self.private_key = private_key

    def generate_private_key(self):
        """
        Генерация закрытого ключа
        """
        self.private_key = ec.generate_private_key(self.curve, default_backend())

    def get_public_key(self):
        """
        Получение открытого ключа по закрытому
        """
        public_key = self.private_key.public_key()
        return public_key

    def get_private_key(self):
        """
        Получение закрытого ключа
        """
        return self.private_key


    def get_group(self):
        return self.curve

    def generate_shared_secret(self, other_public_key):
        """
        Генерация общего секретного ключа на основе чужого открытого ключа
        """
        shared_secret = self.private_key.exchange(ec.ECDH(), other_public_key)
        return shared_secret


def main():
    sender_pk, sender_sk = box_gen_key()
    receiver_pk, receiver_sk = box_gen_key()

    message = b'Secret message'
    kdf_context = b'Zoombase-1-ClientOnly-KDF-KeyMeetingSeed'
    cipher_context = b'Zoombase-1-ClientOnly-Sig-EcryptionKeyMeetingSeed'
    meta = b'meetingUUID'
    
    ciphertext = box_encrypt(sender_sk, receiver_pk, kdf_context, cipher_context, meta, message)
    plaintext = box_decrypt(receiver_sk, sender_pk, kdf_context, cipher_context, meta, ciphertext)
    print("Send message:", message)
    print("Get plaintext:", plaintext)


if __name__ == '__main__':
    main()
