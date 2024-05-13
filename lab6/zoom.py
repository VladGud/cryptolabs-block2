from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization

from ca import CertificationAuthority, User
from crypto_primitives import box_gen_key, box_encrypt, box_decrypt, encrypt_with_aes, decrypt_with_aes


def calculate_binding(meeting_id, meeting_uuid, user_id, hardware_id, ivk, ephemeral_dh_pub_key):
    ivk_public_bytes = ivk.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ephemeral_dh_pub_key_bytes = ephemeral_dh_pub_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    binding = meeting_id + meeting_uuid + user_id + hardware_id + ivk_public_bytes + ephemeral_dh_pub_key_bytes
    sign_context = b'Zoombase-1-ClientOnly-Sig-EncryptionKeyAnnouncement'
    return sign_context, binding


class BulletinBoardParticipant:
    def __init__(self, user_id, hardware_id):
        self.pk = None
        self.signature_key_server = None
        self.ivk = None
        self.meeting_uuid = None
        self.encrypted_mk = None
        self.user_id = user_id
        self.hardware_id = hardware_id


class BulletinBoard:
    def __init__(self, meeting_id):
        self.meeting_id = meeting_id
        self.leader_user_id = None
        self.participants = {}
    
    def add_participant(self, user_id, hardware_id, leader=False):
       self.participants[user_id] = BulletinBoardParticipant(user_id, hardware_id)
       if leader:
           self.leader_user_id = user_id

    def get_participant(self, user_id):
        return self.participants[user_id]

    def get_leader_participant(self):
        if self.leader_user_id:
            return self.participants[self.leader_user_id]
        return None
    
    def get_participants(self):
        return self.participants

class Router:
    def __init__(self):
        self.bulletin_boards = {}

    def create_new_conf(self, meeting_id, participants=None):
        if meeting_id not in self.bulletin_boards:
            self.bulletin_boards[meeting_id] = BulletinBoard(meeting_id)
            for participant in participants:
                self.bulletin_boards[meeting_id].add_participant(*participant)
        else:
            print("Conference exists.")
    
    def get_bulletin_board(self, meeting_id):
        if meeting_id in self.bulletin_boards:
            return self.bulletin_boards[meeting_id]
        else:
            print("Conference doesn't exist.")

    def join_conf(self, meeting_id, user_id, hardware_id):
        if meeting_id in self.bulletin_boards:
            self.bulletin_boards[meeting_id].add_participant(user_id, hardware_id)


class Keyserver(User):
    def __init__(self, name, ca):
        super().__init__(name, ca)

    def init_participant_key(self, router, meeting_id, user_id, hardware_id, ivk, ephemeral_dh_pub_key):
        meeting_uuid = get_random_bytes(10)
        sign_context, binding = calculate_binding(meeting_id, meeting_uuid, user_id, hardware_id, ivk, ephemeral_dh_pub_key)
        signature_key_server = self.sign_data(sign_context + binding)

        board = router.get_bulletin_board(meeting_id)
        bulletin_board_participant = board.get_participant(user_id)

        bulletin_board_participant.meeting_uuid = meeting_uuid
        bulletin_board_participant.pk = ephemeral_dh_pub_key
        bulletin_board_participant.ivk = ivk
        bulletin_board_participant.signature_key_server = (signature_key_server, self.get_certificate())
        print("Init participant key Done")

class BaseParticipant(User):
    def __init__(self, user_id, hardware_id, ca):
        super().__init__(str(user_id), ca)
        self.user_id = user_id
        self.hardware_id = hardware_id

    def init_zoom_session(self, meeting_id, router, keyserver):
        self.pk, self.sk = box_gen_key()
        keyserver.init_participant_key(router, meeting_id, self.user_id, self.hardware_id, self.get_certificate().public_key(), self.pk)


    def join_conf(self, board, meeting_id):
         raise RuntimeError("Use abstract class BaseParticipant")

class Participant(BaseParticipant):
    def init_zoom_session(self, meeting_id, router, keyserver):
        super().init_zoom_session(meeting_id, router, keyserver)

        # Has the conference host logged in?
        # board = router.get_bulletin_board(meeting_id)

    def join_conf(self, board, meeting_id):
        leader_bulletin = board.get_leader_participant()
        if (leader_bulletin is None) and (leader_bulletin.pk  is None):
            raise ValueError("Leader doesn't exist")
        user_board = board.get_participant(self.user_id)

        ivk = leader_bulletin.ivk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pk = leader_bulletin.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binding = meeting_id + leader_bulletin.meeting_uuid + leader_bulletin.user_id + leader_bulletin.hardware_id + ivk + pk
        context_sign = b"Zoombase-1-ClientOnly-Sig-EncryptionKeyAnnouncement"
        signature, cert = leader_bulletin.signature_key_server

        ciphertext = user_board.encrypted_mk

        if not self.verify_data(context_sign + binding, signature, cert):
            raise ValueError("Invalid signature")
        
        meta = meeting_id + user_board.meeting_uuid + leader_bulletin.user_id + self.user_id

        context_kdf = b"Zoombase-1-ClientOnly-KDF-KeyMeetingSeed"
        context_cipher = b"Zoombase-1-ClientOnly-Sig-EncryptionKeyMeetingSeed"

        self.mk = box_decrypt(self.sk, leader_bulletin.pk, context_kdf, context_cipher, meta, ciphertext)

class LeaderParticipant(BaseParticipant):
    def __init__(self, user_id, hardware_id, ca):
        super().__init__(user_id, hardware_id, ca)
        self.master_key = None

    def join_conf(self, board, meeting_id):
        self.master_key = get_random_bytes(32)

        participants = board.get_participants()
        for participant in participants:
            self.connect_new_participant(board, participants[participant].user_id, meeting_id)

    def connect_new_participant(self, board, participant_id, meeting_id):
        participant = board.get_participant(participant_id)
        meeting_uuid = participant.meeting_uuid

        
        ivk =  participant.ivk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pk = participant.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        binding = meeting_id + meeting_uuid + participant.user_id + participant.hardware_id + ivk + pk
        context_sign = b"Zoombase-1-ClientOnly-Sig-EncryptionKeyAnnouncement"
        
        signature, cert = participant.signature_key_server

        if not self.verify_data(context_sign + binding, signature, cert):
            raise ValueError("Invalid signature")

        meta = meeting_id + meeting_uuid + self.user_id + participant.user_id

        context_kdf = b"Zoombase-1-ClientOnly-KDF-KeyMeetingSeed"
        context_cipher = b"Zoombase-1-ClientOnly-Sig-EncryptionKeyMeetingSeed"      

        c = box_encrypt(self.sk, participant.pk, context_kdf, context_cipher, meta, self.master_key)
        participant.encrypted_mk = c

def main():
    ca = CertificationAuthority()
    alice = Participant(b'Alice', get_random_bytes(10), ca)
    bob = LeaderParticipant(b'Leader_Bob', get_random_bytes(10), ca)
    keyserver = Keyserver('Keyserver', ca) 

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

    print("\nGenerate Keyserver certificate...")
    if keyserver.generate_certificate_signing():
        print("Success Keyserver generate_certificate_signing")
    else:
        print("Failed Keyserver generate_certificate_signing")
        return

    router = Router()

    print("Create new conf (Create board)")
    meeting_id = get_random_bytes(10)
    router.create_new_conf(meeting_id,[(alice.user_id, alice.hardware_id, False), (bob.user_id, bob.hardware_id, True)])

    print("Init session on Participant")
    bob.init_zoom_session(meeting_id, router, keyserver)
    print("BOB  is done")
    alice.init_zoom_session(meeting_id, router, keyserver)  
    print("Alice  is done")

    bob.join_conf(router.get_bulletin_board(meeting_id), meeting_id)  
    alice.join_conf(router.get_bulletin_board(meeting_id), meeting_id)


    message = "Test message for ZOOM"
    cipher_message = encrypt_with_aes(message.encode(), bob.master_key)

    print("Send message:", message)

    plaintext = decrypt_with_aes(cipher_message, alice.mk)

    print("Received message:", plaintext.decode())

    print("Negative case:")
    # print("Incorrect sended message")
    # plaintext = decrypt_with_aes(cipher_message + b'1', alice.mk)
    print("Incorrect master key")
    master_key = alice.mk
    master_key = master_key[:-1] + b'1' 
    palintext = decrypt_with_aes(cipher_message, master_key)

if __name__ == '__main__':
    main()
