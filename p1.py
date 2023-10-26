import socket
import struct
import threading
import random
import sys
import time



def dns_query(hostname):

    #header
    id=random.randint(0, 65535)
    qr=0
    opcode=0
    aa=0
    tc=0
    rd=1
    ra=0
    z=0
    rcode=0
    qdcount=1
    ancount=0
    nscount=0
    arcount=0

    flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode
    header = struct.pack("!6H", id, flags, qdcount, ancount, nscount, arcount)


    #question 
    qname_parts = []
    for i in hostname.split():
        qname_parts.append(bytes([len(i)]) + i.encode())
    
    qname_parts.append(b'\x00')
    qname = b''.join(qname_parts)

    qtype = b'\x00\x01'
    qclass = b'\x00\x01'

    question = qname + qtype + qclass

    # Concatenate header and question to form the complete DNS message
    dns_message = header + question

    # Convert the binary DNS message to a hexadecimal representation
    hex_message = dns_message.hex()

    # Return the cleaned hexadecimal message
    return hex_message.replace(" ", "").replace("\n", "")

    pass

print(dns_query("gmu.edu"))

def send_query(dns_query, dns_ip, dns_port=53, timeout=5):
    dns_port=53
    timeout=5

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        dns_query.encode()
        try:
            sock.sendto(dns_query, (dns_ip, dns_port))
        except socket.timeout:
            print("Timeout: DNS query timed out")
            return

def recieve_response():
    pass

def main(): 
    
    # if(len!=2):
    #     print("Error: not enough args !!")
    #     sys.exit(1)

    google_ip = "8.8.8.8"
    hostname = sys.argv[1]
    query = dns_query(hostname)
    send_query(query, google_ip, dns_port=53, timeout=5)
    recieve_response()



if __name__=="__main__":
    main()