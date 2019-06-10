import nacl.encoding
import nacl.signing

signing_key = nacl.signing.SingingKey.generate()
verify_key = signing_key.verify_key

def signMessage(message):
    signed = signing_key.sign(bytes(massage,'utf-8'))

def serialzeVerifyKey():
    verify_key_hex = verify_key.encode(encodeer=nacl.encoding.HexEncoder)

