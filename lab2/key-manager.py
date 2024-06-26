import os
import hmac
import hashlib
import base64
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

class PasswordManager:
    def __init__(self, master_password_file):
        self.master_password_file = master_password_file
        self.data_file = 'passwords.json'
        self.hmac_file = 'passwords_hmac.txt'

    def _load_key(self, master_password_file):
        if os.path.exists(master_password_file):
            with open(master_password_file, 'rb') as f:
                key_data = f.read().split(b'\n')
                master_password = key_data[0]
                pbkdf2_salt = key_data[1]
                hmac_salt = key_data[2]

        else:
            master_password = get_random_bytes(16)
            pbkdf2_salt = get_random_bytes(16)
            hmac_salt = get_random_bytes(16)
            with open(master_password_file, 'wb') as f:
                f.write(master_password + b'\n' + pbkdf2_salt + b'\n' + hmac_salt) 

        return master_password, pbkdf2_salt, hmac_salt

    def _init_hmac_keys(self):
        master_password, pbkdf2_salt, hmac_salt = self._load_key(self.master_password_file)

        main_key = self.derive_key(master_password, pbkdf2_salt, hmac_flag=False)
        self.hmac_key = self.derive_key(main_key, hmac_salt, hmac_flag=True)

    def _init_enc_keys(self, enc_salt):
        master_password, pbkdf2_salt, hmac_salt = self._load_key(self.master_password_file)

        main_key = self.derive_key(master_password, pbkdf2_salt, hmac_flag=False)
        self.enc_key = self.derive_key(main_key, hmac_salt, hmac_flag=True)

    def derive_key(self, password, salt, hmac_flag=False):
        if hmac_flag:
            return hmac.new(password, salt, hashlib.sha256).digest()
        else:
            return hashlib.pbkdf2_hmac('sha256', password, salt, 1000000, dklen=32)

    def encrypt(self, additional_data, data):
        cipher = AES.new(self.enc_key, AES.MODE_GCM)
        cipher.update(additional_data.encode('utf-8'))
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return bytes(cipher.nonce + tag + ciphertext)

    def decrypt(self, additional_data, data):
        decoded_data = eval(data)
        nonce = decoded_data[:16]
        tag = decoded_data[16:32]
        ciphertext = decoded_data[32:]
        cipher = AES.new(self.enc_key, AES.MODE_GCM, nonce)
        cipher.update(additional_data.encode('utf-8'))
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    def generate_hmac(self, data):
        return hmac.new(self.hmac_key, data.encode('utf-8'), hashlib.sha256).hexdigest()

    def save_password(self, domain, password):
        self._init_hmac_keys()

        with open(self.hmac_file, 'r') as file:
            saved_hmac_file = file.readline()

        with open(self.data_file, 'r') as file:
            try:
                data = json.load(file)
            except json.decoder.JSONDecodeError:
                data = {}

        if (data != {}) and (self.generate_hmac(json.dumps(data)) != saved_hmac_file):
            raise ValueError("HMAC passwords file incorrect")

        enc_salt = get_random_bytes(16)
        self._init_enc_keys(enc_salt)

        hmac_domain = self.generate_hmac(domain)
        encrypted_password = self.encrypt(hmac_domain, password)
        print(encrypted_password)
        data[hmac_domain] = enc_salt.hex() + str(encrypted_password)

        with open(self.data_file, 'w') as file:
            json.dump(data, file)

        # Update HMAC file
        with open(self.hmac_file, 'w') as hmac_file:
            hmac_file.write(self.generate_hmac(json.dumps(data)))

    def get_password(self, domain):
        self._init_hmac_keys()

        with open(self.hmac_file, 'r') as file:
            saved_hmac_file = file.readline()

        with open(self.data_file, 'r') as file:
            data = json.load(file)

            if self.generate_hmac(json.dumps(data)) != saved_hmac_file:
                raise ValueError("HMAC passwords file incorrect")

            hmac_domain = self.generate_hmac(domain)
            if hmac_domain in data:
                enc_salt = data[hmac_domain][:32]
                self._init_enc_keys(bytes.fromhex(enc_salt))
                encrypted_password = data[hmac_domain][32:]
                return self.decrypt(hmac_domain, encrypted_password)
            else:
                return None

# Пример использования:
manager = PasswordManager("masterpassword")

# Сохранение пароля для домена
example_com = "example.io"
print("Save password for:", example_com)
manager.save_password(example_com, "password12")
#print ct

ozon_ru = "example.ru"
print("Save password for:", ozon_ru)
manager.save_password("example.ru", "password22")
#print ct

google_com = "example.com"
print("Save password for:", google_com)
manager.save_password(google_com, "password12")
#print ct

# Получение пароля для домена
password = manager.get_password("example.io")
print("Password for example.com:", password)
