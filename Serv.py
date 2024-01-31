import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import sys
import logging

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
DNS_HEADER_LENGTH = 12
# TODO make some DNS database with IPs connected to regexs
IP = '192.168.1.1'

class DNSHandler():
    def handle(self, packet):
        data = packet #self.request[0].strip()

        # If request doesn't even contain full header, don't respond.
        if len(data) < DNS_HEADER_LENGTH:
            return

        # Try to read questions - if they're invalid, don't respond.
        try:
            all_questions = self.dns_extract_questions(data)
        except IndexError:
            return

        # Filter only those questions, which have QTYPE=A and QCLASS=IN
        # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
        accepted_questions = []
        for question in all_questions:
            name = str(b'.'.join(question['name']), encoding='UTF-8')
            logging.info("Questions received from the client:")
            if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
                accepted_questions.append(question)
                logging.info(name)
            else:
                logging.info(name)

        response = (
            self.dns_response_header(data) +
            self.dns_response_questions(accepted_questions) +
            self.dns_response_answers(accepted_questions)
        )
        #print(response)
        #print("len of res: {0}".format(len(response)))
        return response
        #socket.sendto(response, self.client_address)

    def dns_extract_questions(self, data):
        """
        Extracts question section from DNS request data.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        questions = []
        # Get number of questions from header's QDCOUNT
        n = (data[4] << 8) + data[5]
        # Where we actually read in data? Start at beginning of question sections.
        pointer = DNS_HEADER_LENGTH
        # Read each question section
        for i in range(n):
            question = {
                'name': [],
                'qtype': '',
                'qclass': '',
            }
            length = data[pointer]
            # Read each label from QNAME part
            while length != 0:
                start = pointer + 1
                end = pointer + length + 1
                question['name'].append(data[start:end])
                pointer += length + 1
                length = data[pointer]
            # Read QTYPE
            question['qtype'] = data[pointer+1:pointer+3]
            # Read QCLASS
            question['qclass'] = data[pointer+3:pointer+5]
            # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
            pointer += 5
            questions.append(question)
        return questions

    def dns_response_header(self, data):
        """
        Generates DNS response header.
        See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
        """
        header = b''
        # ID - copy it from request
        header += data[:2]
        # QR     1    response
        # OPCODE 0000 standard query
        # AA     0    not authoritative
        # TC     0    not truncated
        # RD     0    recursion not desired
        # RA     0    recursion not available
        # Z      000  unused
        # RCODE  0000 no error condition
        header += b'\x80\x00'
        # QDCOUNT - question entries count, set to QDCOUNT from request
        header += data[4:6]
        # ANCOUNT - answer records count, set to QDCOUNT from request
        header += data[4:6]
        # NSCOUNT - authority records count, set to 0
        header += b'\x00\x00'
        # ARCOUNT - additional records count, set to 0
        header += b'\x00\x00'
        return header

    def dns_response_questions(self, questions):
        """
        Generates DNS response questions.
        See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
        """
        sections = b''
        for question in questions:
            section = b''
            for label in question['name']:
                # Length octet
                section += bytes([len(label)])
                section += label
            # Zero length octet
            section += b'\x00'
            section += question['qtype']
            section += question['qclass']
            sections += section
        return sections

    def dns_response_answers(self, questions):
        """
        Generates DNS response answers.
        See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
        """
        records = b''
        for question in questions:
            record = b''
            for label in question['name']:
                # Length octet
                record += bytes([len(label)])
                record += label
            # Zero length octet
            record += b'\x00'
            # TYPE - just copy QTYPE
            # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
            record += question['qtype']
            # CLASS - just copy QCLASS
            # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
            record += question['qclass']
            # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
            # should not be cached.
            record += b'\x00\x00\x00\x00'
            # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
            # In case of QTYPE=A and QCLASS=IN, RDLENGTH=4.
            record += b'\x00\x04'
            # RDATA - in case of QTYPE=A and QCLASS=IN, it's IPv4 address.
            record += b''.join(map(
                lambda x: bytes([int(x)]),
                IP.split('.')
            ))
            records += record
        return records

logging.info("Generating RSA Key pair")
key = RSA.generate(4096)
SrPubKey = key.publickey().exportKey()
SrPriKey = key.exportKey()

#Declartion
mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostbyname(socket.getfqdn())
port = 8888

if host == "127.0.1.1":
    import commands
    host = commands.getoutput("hostname -I")
logging.info("Starting DNS server on host: " + host)

#Prevent socket.error: [Errno 98] Address already in use
#mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

mysocket.bind((host, port))
mysocket.listen(1)
while True:
    c = None
    try:
        c, addr = mysocket.accept()

        #Wait until data is received.
        data = c.recv(10)
        data = data.decode()
        logging.info("Received: " + data)
    
        ClPubKey = c.recv(1024)        

        #Remove extra characters
        ClPubKey = ClPubKey.replace(b"public_key=", b'')
        ClPubKey= ClPubKey.replace(b"\r\n", b'')
        
        logging.info("Client public key received")
        #print(ClPubKey)

        c.send(b'server_public_key=' + SrPubKey + b'\n')
        logging.info("Sending public key to client.")
    
        #print("server private key:\n")
        #print(SrPriKey)

        #Convert string to key
        client_public_key = RSA.importKey(ClPubKey)
        Cl_publickey = PKCS1_OAEP.new(client_public_key)

        logging.info("DNS request packet received")
        packet = c.recv(1024)
        #print(packet)
        #print("Done\n")

        logging.info("Building DNS response packet")
        h = DNSHandler()
        res = h.handle(packet)

        logging.info("Encrypting and sending DNS response using clients public key")
        x = Cl_publickey.encrypt(res)
        #print(x)
        c.send(x)

        logging.info("Sending server private key to client as a signature")
        #Chunking and sending private key
        Ky = SrPriKey.decode()
        chunks=[]
        for i in range(0,len(Ky),470):
            chunks.append(Ky[i:i+470])

        #print(str(len(chunks)).encode())
        c.send(str(len(chunks)).encode())

        for i in range(len(chunks)):
            c.send(Cl_publickey.encrypt(chunks[i].encode()))
            #print(Cl_publickey.encrypt(chunks[i].encode()))
        c.close()
        break

    except KeyboardInterrupt:
        if c:
            c.close()
        logging.info("Quitting")
        break


#Server to stop
#c.send(b"Server stopped\n")
logging.info("Server stopped")