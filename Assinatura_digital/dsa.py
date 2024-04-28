from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

class DSAKeys:
    def __init__(self):
        pass

    def generate_keys(self):
        key =  DSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        return private_key, public_key

    def save_keys(self, private_key, public_key):
        with open("dsa.priv", "wb") as f:
            f.write(private_key)

        with open("dsa.pub", "wb") as f:
            f.write(public_key)
    
    def load_keys(self):
        with open("dsa.priv", "rb") as f:
            private_key = DSA.import_key(f.read())
        with open("dsa.pub", "rb") as f:
            public_key = DSA.import_key(f.read())

        return private_key, public_key
    
    def sign(self, message):
        private_key, _ = self.load_keys()
        hash_obj = SHA256.new(message.encode())
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        return signature