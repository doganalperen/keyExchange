from Crypto.Cipher import AES
import json
import sys
from Crypto.Util.Padding import unpad
from ast import literal_eval

read_data = sys.stdin.read()

index1 = read_data.find('{')
index2 = read_data.find('}')
#index3 = read_data.find('{', index2)
#index4 = read_data.find('}', index3)


incoming_data = read_data[index1:index2+1]
#salt_data = read_data[index3:index4+1]

#salt = json.loads(salt_data)["salt"]

#data = json.loads(incoming_data)
ciphertext = json.loads(incoming_data)data["data"]

with open('connectionKey.pem', 'rb') as connectionKeyFile:
    connectionKey = connectionKeyFile.read()

#derived_key = HKDF(algorithm=hashes.SHA512(), length=64, salt=salt, info=b'label').derive(shared_key)

cipher = AES.new(connectionKey[:16], mode=AES.MODE_CBC, iv=connectionKey[16:32])
plaintext = unpad(cipher.decrypt(convert((ciphertext))),16)
sys.stdout.flush()
sys.stdout.write(plaintext.decode('utf-8'))