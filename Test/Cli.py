import socket
import sys 
import os 
import signal
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(4096)
PubKey = key.publickey().exportKey()
PriKey = key.exportKey()
Cl_privatekey = RSA.importKey(PriKey)
client_private_key = PKCS1_OAEP.new(Cl_privatekey)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "10.10.130.11"
port = 8888

#server.bind(("10.10.130.11", 8880))
server.connect((host, port))

#Tell server that connection is OK
server.sendall(b"Client: OK")


#Send Client Public Key to Server
server.send(b'public_key=' + PubKey + b'\n')
print("Public key sent to server.")

SrPubKey = server.recv(1024)
SrPubKey = SrPubKey.replace(b"server_public_key=", b'')
SrPubKey= SrPubKey.replace(b"\r\n", b'')
        
print("server public key :\n")
print(SrPubKey)

encmsg = server.recv(1024)
print(encmsg)

z = client_private_key.decrypt(encmsg)
print(z.decode())

noOfChunks = server.recv(1)
noOfChunks = int(noOfChunks.decode())
print(noOfChunks)
encSrPriKey = []
for i in range(noOfChunks):
    encSrPriKey.append(server.recv(512))
    print(encSrPriKey[0])

print(len(encSrPriKey))

srPriKey = b''
for i in range(len(encSrPriKey)):
    srPriKey += client_private_key.decrypt(encSrPriKey[i])

print("Server private key")
print(srPriKey)

Sr_public_key = RSA.importKey(SrPubKey)
server_public_key = PKCS1_OAEP.new(Sr_public_key)


Sr_privatekey = RSA.importKey(srPriKey)
server_private_key = PKCS1_OAEP.new(Sr_privatekey)

print("Encrypting \'Test\' using server public key")
x = server_public_key.encrypt(b'Test')
print(x)
z = server_private_key.decrypt(x)
print("Decrypting using received server private key:")
print(z)

print(server.recv(1024).decode()) #Quit server response
server.close()