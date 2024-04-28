from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class DSSVerifier(object):
    def __init__(self) -> None:
        self.verifier = None
        self.key = None
        pass

    def set_key(self, key):
        self.key = key

    def verify(self, message, signature):
        hashed_message = SHA256.new(message)
        self.verifier = DSS.new(self.key, 'fips-186-3')

        try:
            self.verifier.verify(hashed_message, signature)
            return True
        except ValueError:
            return False