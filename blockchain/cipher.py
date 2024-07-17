from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from helpers.utils import sxor
import codecs


class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = key

    def encrypt(self, plain_text, iv=None):
        if iv is None:
            iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))).decode("utf-8")

    def decrypt(self, encrypted_text, iv=None):
        encrypted_text = b64decode(encrypted_text)
        if iv is None:
            iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_text[AES.block_size:]), AES.block_size).decode("utf-8")


if __name__ == "__main__":
    ivv = 16 * b'\x00'
    kkk = codecs.decode('3ea828a5b59b4a356ff2ef33baf2b29f', 'hex_codec')
    print(kkk, " - kkk")
    nonce = "4568519763598209396326848692811768078913728193662584577088437018"
    proof = "fc340c795731099035871414ce28f2a8d22eb1085cbd34df31ed6d91f4f47e77"
    xored = sxor(nonce, proof)
    print(xored)
    encrypted = AESCipher(kkk).encrypt(xored, ivv)
    print("Encrypted result: " + encrypted)
    decrypted = AESCipher(kkk).decrypt(encrypted, ivv)
    print("Decrypted: " + decrypted)
