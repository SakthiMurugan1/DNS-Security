from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#key = RSA.generate(4096)
#f = open('my_rsa_public.pem', 'wb')
#f.write(key.publickey().exportKey('PEM'))
#f.close()
#f = open('my_rsa_private.pem', 'wb')
#f.write(key.exportKey('PEM'))
#f.close()

f = open('my_rsa_public.pem', 'rb')
f1 = open('my_rsa_private.pem', 'rb')
key = RSA.importKey(f.read())
cipher = PKCS1_OAEP.new(key)
key1 = RSA.importKey(f1.read())
cipher2 = PKCS1_OAEP.new(key1)

a=''
for i in range(10,196):
    a+=str(i)

a+='12'
print(len(a))
x = cipher.encrypt(a.encode())

print(x)

z = cipher2.decrypt(x)
print(z)