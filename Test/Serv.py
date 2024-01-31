import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(4096)
SrPubKey = key.publickey().exportKey()
SrPriKey = key.exportKey()

#key = RSA.generate(4096)
#PubKey = key.publickey().exportKey()

#Declartion
mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostbyname(socket.getfqdn())
port = 8888
encrypt_str = b"encrypted_message="

if host == "127.0.1.1":
    import commands
    host = commands.getoutput("hostname -I")
print("host = " + host)

#Prevent socket.error: [Errno 98] Address already in use
#mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

mysocket.bind((host, port))
mysocket.listen(5)
c, addr = mysocket.accept()

#Wait until data is received.
data = c.recv(10)
data = data.decode()
print(data)
    
ClPubKey = c.recv(1024)        

#Remove extra characters
ClPubKey = ClPubKey.replace(b"public_key=", b'')
ClPubKey= ClPubKey.replace(b"\r\n", b'')
        
print("client public key:\n")
print(ClPubKey)

c.send(b'server_public_key=' + SrPubKey + b'\n')
print("Public key sent to client.")
    
print("server private key:\n")
print(SrPriKey)

#Convert string to key
client_public_key = RSA.importKey(ClPubKey)
Cl_publickey = PKCS1_OAEP.new(client_public_key)

x = Cl_publickey.encrypt(b"dddddd")
print(x)
c.send(x)

#Chunking and sending private key
Ky = SrPriKey.decode()
chunks=[]
for i in range(0,len(Ky),470):
    chunks.append(Ky[i:i+470])

print(str(len(chunks)).encode())
c.send(str(len(chunks)).encode())

for i in range(len(chunks)):

    c.send(Cl_publickey.encrypt(chunks[i].encode()))
    print(Cl_publickey.encrypt(chunks[i].encode()))


#Server to stop
c.send(b"Server stopped\n")
print("Server stopped")
c.close()