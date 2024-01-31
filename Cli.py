import struct
import socket
import argparse
import dnslib
import sys 
import os 
import signal
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)

class DnsQueryBuilder:
    def __init__(self):
        self.url = ""
        self.rtype = "AA"
    def build_query_packet(self, url, rtype):
        packet = struct.pack(">H", 1)  # Query Ids (Just 1 default)
        packet += struct.pack(">H", 256)  # Flags AA RA RD TC
        packet += struct.pack(">H", 1)  # Questions
        packet += struct.pack(">H", 0)  # Answers
        packet += struct.pack(">H", 0)  # Authorities
        packet += struct.pack(">H", 0)  # Additional
                
        split_url = url.split(".")
        try:
            #print("in try block")
            if isinstance(int(split_url[0]), int):
                split_url.append('in-addr')
                split_url.append('arpa')
                i = 3
                while i != -1:
                    packet += struct.pack("B", len(split_url[i]))
                    for byte in split_url[i]:
                        packet += struct.pack("c", byte.encode('utf-8'))
                    i -= 1
            packet += struct.pack("B", len(split_url[4]))
            for byte in split_url[4]:
                packet += struct.pack("c", byte.encode('utf-8'))
            packet += struct.pack("B", len(split_url[5]))
            for byte in split_url[5]:
                packet += struct.pack("c", byte.encode('utf-8'))

            packet += struct.pack("B", 0)  # End of String
            packet += struct.pack(">H", 12) # Hardcoded default to inverse query because if code enters this section it would be for inverse query
            packet += struct.pack(">H", 1)  # Query Class

        except:            
            for part in split_url:
                packet += struct.pack("B", len(part))
                for byte in part:
                    packet += struct.pack("c", byte.encode('utf-8'))
                                
            packet += struct.pack("B", 0)  # End of String
            if rtype == b"CNAME" or rtype == "CNAME":
                packet += struct.pack(">H", 5)  # Query Type 2-NS, 15-MX, 5-CNAME, 12-PTR, 28-AAAA
            elif rtype == b"MX" or rtype == "MX":
                packet += struct.pack(">H", 15)
            elif rtype == b"PTR" or rtype == "PTR":
                packet += struct.pack(">H", 12)
            elif rtype == b"AAAA" or rtype == "AAAA":
                packet += struct.pack(">H", 28)
            else:
                packet += struct.pack(">H", 1)

            packet += struct.pack(">H", 1)  # Query Class

        return packet

#Creating an ArgumentParser object
parser = argparse.ArgumentParser(description='Custom nslookup')
#Adding Arguments into ArgumentParser object
parser.add_argument('url', help='Enter URl for DNS Query ')
parser.add_argument('--dns_ip', default="127.0.0.1", help='IP Adress of DNS Server, eg: --dns_ip 8.8.8.8')
parser.add_argument('--rtype', default="AA", choices=["AA", "MX", "CNAME", "PTR", "AAAA"], help='Request Query type, eg: --rtype AA, NS, CNAME, MX, AAAA')
args = parser.parse_args()
url = args.url
dns = args.dns_ip
if (dns == "127.0.0.1"):
    dns = socket.gethostbyname(socket.getfqdn())
rtype = args.rtype.encode('utf-8')
#print(dns)

logging.info("Url: {0}".format(url))     
logging.info("DNS Server: {0}".format(dns)) 

logging.info("Generating RSA Key pair")
key = RSA.generate(4096)
PubKey = key.publickey().exportKey()
PriKey = key.exportKey()
Cl_privatekey = RSA.importKey(PriKey)
client_private_key = PKCS1_OAEP.new(Cl_privatekey)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = dns
port = 8888

logging.info("Connecting to DNS server")
server.connect((host, port))

#Tell server that connection is OK
server.sendall(b"Client: OK")
logging.info("Clinet: OK Sent")

#Send Client Public Key to Server
server.send(b'public_key=' + PubKey + b'\n')
logging.info("Public key sent to server.")

SrPubKey = server.recv(1024)
SrPubKey = SrPubKey.replace(b"server_public_key=", b'')
SrPubKey= SrPubKey.replace(b"\r\n", b'')
        
logging.info("Server public key received")
#print(SrPubKey)

# Sending the packet
builder = DnsQueryBuilder()
packet = builder.build_query_packet(url, rtype)

logging.info("Building and sending DNS request packet:")

server.send(bytes(packet))
#sock.sendto(bytes(packet), (dns, 53))

encmsg = server.recv(1024)
logging.info("Encrypted DNS response received")
#print(encmsg)

noOfChunks = server.recv(1)
noOfChunks = int(noOfChunks.decode())
#print(noOfChunks)
encSrPriKey = []
for i in range(noOfChunks):
    encSrPriKey.append(server.recv(512))
    #print(encSrPriKey[0])

#print(len(encSrPriKey))

srPriKey = b''
for i in range(len(encSrPriKey)):
    srPriKey += client_private_key.decrypt(encSrPriKey[i])

logging.info("Server private key received with the encrypted response")
#print(srPriKey)

Sr_public_key = RSA.importKey(SrPubKey)
server_public_key = PKCS1_OAEP.new(Sr_public_key)


Sr_privatekey = RSA.importKey(srPriKey)
server_private_key = PKCS1_OAEP.new(Sr_privatekey)

Test = b'Test'
logging.info("Encrypting {0} using server public key".format(Test.decode()))
x = server_public_key.encrypt(Test)
#print(x)
TestRes = server_private_key.decrypt(x)
logging.info("Decrypting test message using received server private key:")
#print(TestRes)
if(TestRes != Test):
    logging.warning("Private Key and Public Key Recieved are not a pair. Data might me tampered. Quitting...")
    exit()
else:
    logging.info("Authentication of data complete")

logging.info("Decrypting response from server")
z = client_private_key.decrypt(encmsg)
#print("Response:\n")
#print(z)

result = dnslib.DNSRecord().parse(z).format()

line = result.splitlines()
for i in range(len(line)):
    #print(line[i])
    words = line[i].split(' ')
    #print(words)
    for i in range(len(words)):
        if words[i] == 'Question:':
            print('\nHost name: ' + words[i+1].strip(".'"))
        elif words[i] == 'rtype=A' or words[i] == 'rtype=AAAA':
            ip = words[-1][7:].strip("'>")
            if (len(ip) > 20):
                print("IPv6: " + ip)
            else:
                print("IPv4: " + ip)
        elif words[i] == 'rtype=MX':
            print("MX: " + words[-1].strip(".'>"))
        elif words[i] == 'rtype=CNAME':
            print("CNAME: " + words[-1][7:].strip(".'>"))
        elif words[i] == 'rtype=PTR':
            print("Inverse: " + words[-1][7:].strip(".'>"))

print("\n", end="")
#print(server.recv(1024).decode()) #Quit server response
logging.info("Quitting...")
server.close()