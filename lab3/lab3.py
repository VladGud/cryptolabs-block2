from ca import CertificationAuthority, User, generate_fake_certificate

import random
import numpy
import string
import hashlib
from numpy.linalg import inv


class DispersalAlgorithm:
    @staticmethod
    def generate_vandermonds_matrix(col : int, row : int, indx_list = None):
        field = 2 ** 8

        A = list()
        for i in range(2, row + 2):
            a = list()
            for j in range(0, col):
                a.append(pow(i, j, field))
            A.append(a)

        if indx_list == None:
            return A

    def __init__(self, m : int, n : int):
        self.m, self.n = m, n
        self.A = self.generate_vandermonds_matrix(m, n)

    def dispersal(self, data : bytes):
        M = list()

        for i in range(0, len(data) //self.m):
            S = list()
            for j in range(0, self.m):
                S.append(data[(i) * self.m + j])
            M.append(S)
        M = numpy.array(M).transpose()

        F = numpy.matmul(self.A, M)

        return F


    def recovery(self, F, indx_list):
        A_of_indx = list()
        for i in indx_list:
            A_of_indx.append(self.A[i])

        A = inv(A_of_indx)
        M = numpy.matmul(A, numpy.array(F))

        message = ''
        M = M.transpose()
        for item_1 in M:
            for item_2 in item_1:
                try:
                    message += chr(round(item_2))
                except ValueError:
                    continue

        return bytes(message, 'utf-8')


class Gateway(User):
    def __init__(self, storage_devices, dispersal_algorithm, name, ca):
        User.__init__(self, name, ca)
        self.dispersal_algorithm = dispersal_algorithm
        self.storage_devices = storage_devices

    def set_data(self, data, signature, issuer_certificate):
        if not self.verify_data(data, signature, issuer_certificate):
            return

        for i in range(len(self.storage_devices)):
            self.storage_devices[i].set_data(data, signature, issuer_certificate)
    
    def get_data_from_part(self):
        hash_array = list()
        hash_array_count = list()

        for i in range(len(self.storage_devices)):
            hash_array.append(0)
            hash_array_count.append(0)

        for device in self.storage_devices:
            hash_item = device.get_part()[1]
            for indx in range(len(self.storage_devices)):
                if hash_array[indx] == 0:
                    hash_array[indx] = hash_item[indx]
                    hash_array_count[indx] = 1
                    continue
                hash_array_count[indx] += 1
        return_part_array = list()
        index_return_part_array = list()
        for indx in range(len(self.storage_devices)):
            if len(return_part_array) == self.dispersal_algorithm.m:
                break
            if hash_array_count[indx] == max(hash_array_count):
                return_part_array.append(self.storage_devices[indx].get_part()[0])
                index_return_part_array.append(indx)
        
        if len(return_part_array) < self.dispersal_algorithm.m:
            raise ValueError(f'Recovery failed. Not much number {self.dispersal_algorithm.m} Storage device')

        source_value = self.dispersal_algorithm.recovery(return_part_array, index_return_part_array)

        return source_value, self.sign_data(source_value)


class StorageDevice(User):
    def __init__(self, identificator, dispersal_algorithm, name, ca):
        User.__init__(self, name, ca)
        self.identificator = identificator
        self.dispersal_algorithm = dispersal_algorithm
        self.part_list = None

    def set_data(self, data, signature, issuer_certificate):
        if not self.verify_data(data, signature, issuer_certificate):
            return

        parts = self.dispersal_algorithm.dispersal(data)
        hash_parts = list()
        for item in parts:
            hash_object = hashlib.sha256()
            for item_numpy in item:
                hash_object.update(str(item_numpy).encode())
            hash_parts.append(hash_object.digest())

        self.part_list = (parts[self.identificator], hash_parts, signature)

    def get_part(self):
        return self.part_list 


def generate_random_ascii(length):
    ascii_characters = string.ascii_letters + string.digits + string.punctuation + string.whitespace
    random_ascii = ''.join(random.choice(ascii_characters[:127]) for _ in range(length))
    return random_ascii.encode('ascii')


def main():
    n = 8
    m = 4
    dispersal_algorithm = DispersalAlgorithm(m, n)

    byte_array = generate_random_ascii(n*m)

    print(byte_array)

    ca = CertificationAuthority()
    alice = User("Alice", ca)

    print("\nGenerate Alice certificate...")
    if alice.generate_certificate_signing():
        print("Success Alice generate_certificate_signing")
    else:
        print("Failed Alice generate_certificate_signing")
        return

    sd_list = list()
    for i in range(0, n):
        name = f"StorageData{i}"
        sd = StorageDevice(i, dispersal_algorithm, name, ca)
        
        print(f"\nGenerate {name} certificate...")
        if alice.generate_certificate_signing():
            print(f"Success {name} generate_certificate_signing")
        else:
            print(f"Failed {name} generate_certificate_signing")
            return

        sd_list.append(sd)

    gw = Gateway(sd_list, dispersal_algorithm, "Gw", ca)

    print("\nGenerate Gateway certificate...")
    if gw.generate_certificate_signing():
        print("Success Gateway generate_certificate_signing")
    else:
        print("Failed Gateway generate_certificate_signing")
        return

    signature = alice.sign_data(byte_array)
    print("\nSend data to Gateway")
    gw.set_data(byte_array, signature, alice.get_certificate())
    print("\nSuccess data stored on storage device")

    print("\nGet data from Gateway")
    recovery_data, signature = gw.get_data_from_part()
    print(byte_array, "==", recovery_data, recovery_data==byte_array)

    print("\nUser verify signature:")
    if alice.verify_data(recovery_data, signature, gw.get_certificate()):
        print("Success verify signature from gw")
    else:
        print("Failed data")

    for i in range(m):
        sd_list[i].part_list = (numpy.array(numpy.random.randint(0, 50, size=n)), generate_random_ascii(10))

    print("\nGet data from Gateway with 4 invalid storage data")
    recovery_data, _ = gw.get_data_from_part()
    print("\nSuccess: ", recovery_data)

    print("\nNegative Test:")
    # gw.storage_devices = gw.storage_devices[:3]
    # recovery_data = gw.get_data_from_part()

    # gw.set_data(byte_array, signature, gw.get_certificate())
    #gw.set_data(byte_array, signature, generate_fake_certificate())

    print("\nGet data from Gateway with 5 invalid storage data")
    sd_list[4].part_list = (numpy.array(numpy.random.randint(0, 1, size=n)), generate_random_ascii(10))
    recovery_data, _ = gw.get_data_from_part()
    print("Byte array == Recovery Value: ", recovery_data == byte_array)
    print("Recovery Value:", recovery_data)

if __name__ == '__main__':
    main()