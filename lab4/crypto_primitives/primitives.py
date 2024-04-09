from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import getStrongPrime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_aes_keys(shared_secret, additional_salt):
    # Преобразование общего секрета в байтовую строку
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big') if type(shared_secret) != type(bytes()) \
                          else shared_secret

    # Формирование соли (salt) для первого ключа
    salt = b"salt" + additional_salt
    # Создание объекта HKDF для первого ключа
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Длина ключа AES (256 бит)
        salt=salt,
        info=b'',
        backend=default_backend()
    )
    # Вычисление производного ключа для первого ключа
    aes_key = hkdf.derive(shared_secret_bytes)

    return aes_key


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
    
    return (iv, ciphertext, tag)

def decrypt_with_aes(iv, ciphertext, tag, aes_key):
    """
    Дешифрование текста с использованием ключа AES в режиме GCM
    """
    # Инициализация шифра AES в режиме GCM с заданным IV и тегом
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Расшифрование текста
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


def generate_mac_with_aes(message, aes_key):
    """
    Генерация кода аутентичности сообщения (MAC) с использованием ключа AES
    """
    # Инициализация алгоритма HMAC-SHA256
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    
    # Обновление алгоритма хеширования HMAC с сообщением
    h.update(message)
    
    # Вычисление кода аутентичности
    mac = h.finalize()
    
    return mac


class DiffieHellmanParty:
    """
    Класс для участника протокола Диффи-Хеллмана
    """

    def __init__(self, prime=None, generator=None):
        self.prime = int(getStrongPrime(512)) if prime is None else prime
        self.generator = random.randint(2, self.prime - 2) if generator is None else generator
        self.private_key = self.generate_private_key()
        self.public_key = self.get_public_key()

    def generate_private_key(self):
        """
        Генерация закрытого ключа
        """
        return random.randint(2, self.prime - 2)

    def get_public_key(self):
        """
        Получение открытого ключа по закрытому
        """
        return pow(self.generator, self.private_key, self.prime)

    def get_generator(self):
        return self.generator

    def get_group(self):
        return self.prime

    def generate_shared_secret(self, other_public_key):
        """
        Генерация общего секретного ключа на основе чужого открытого ключа
        """
        return pow(other_public_key, self.private_key, self.prime)

class EllipticCurveDiffieHellmanParty:
    """
    Класс для участника протокола Диффи-Хеллмана на эллиптической кривой
    """

    def __init__(self, curve=None, generator=None):
        self.curve = curve if curve is not None else ec.SECP256R1()
        self.private_key = self.generate_private_key()
        self.public_key = self.get_public_key()

    def generate_private_key(self):
        """
        Генерация закрытого ключа
        """
        private_key = ec.generate_private_key(self.curve, default_backend())
        return private_key

    def get_public_key(self):
        """
        Получение открытого ключа по закрытому
        """
        public_key = self.private_key.public_key()
        return public_key

    def get_generator(self):
        pass

    def get_group(self):
        return self.curve

    def generate_shared_secret(self, other_public_key):
        """
        Генерация общего секретного ключа на основе чужого открытого ключа
        """
        shared_secret = self.private_key.exchange(ec.ECDH(), other_public_key)
        return shared_secret

# Пример использования:
if __name__ == "__main__":
    # Создание обмена ключами
    party_a = EllipticCurveDiffieHellmanParty()
    party_b = EllipticCurveDiffieHellmanParty(party_a.get_group(), party_a.get_generator())

    shared_secret = party_a.generate_shared_secret(party_b.get_public_key())
    nonce = get_random_bytes(64)

    # Вывод общего секретного ключа на каждой стороне
    print("Shared secret computed by party A:", derive_aes_keys(shared_secret, nonce))
    print("Shared secret computed by party B:", derive_aes_keys(party_b.generate_shared_secret(party_a.get_public_key()), nonce))
