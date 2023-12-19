from crypto_algorithms import generate_key
from storage_backend import KeyStorage

class KeyManager:
    def __init__(self):
        self.storage = KeyStorage()

    def create_key(self, key_type):
        key = generate_key(key_type)
        key_id = self.storage.store_key(key)
        return key_id

    def get_key(self, key_id):
        return self.storage.retrieve_key(key_id)

    def revoke_key(self, key_id):
        self.storage.delete_key(key_id)