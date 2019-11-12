import argparse
import socket
import select
import basicim_nugget_pb2
import sys
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import signal



parser = argparse.ArgumentParser()
parser.add_argument('-n', dest='nickname', help='your nickname', required=True)
parser.add_argument('-s', dest='servername', help='servername', required=True)
parser.add_argument('-p', dest='port', help='port', required=True)
parser.add_argument('-c', dest='confidkey', help='confidkey', required=True)
parser.add_argument('-a', dest='authkey', help='authkey', required=True)

args = parser.parse_args()

#Handles CTRL-C
def signal_handler(sig, frame):
    sys.exit(0)

#Encrypt then MAC scheme
def encryption(confidkey, authkey, user_input):

    blocksize = 16

    iv = get_random_bytes(16) #generate random IV

    #Enable the keys to be 256 bytes so they can work with ABS

    ck = hashlib.sha256(confidkey.encode('utf-8')).digest()

    ak = hashlib.sha256(authkey.encode('utf-8')).digest()

    #Serialization
    nugget = basicim_nugget_pb2.BasicIMNugget()
    nugget.nickname = args.nickname
    nugget.message = user_input
    serialized = nugget.SerializeToString()

    #message is 16 bytes (or some multiple of 16)
    msg = pad(serialized, blocksize)

    #Encryptor
    ciph1 = AES.new(ck, AES.MODE_CBC, iv)

    ct = ciph1.encrypt(msg) #Encryption

    #hmac generation for authentication
    hMAC = hmac.new(key=ak, msg=ct, digestmod=hashlib.sha256).digest()

    #length of ciphertext (just in case)
    length = len(ct)

    #length of ciphertext in bytes
    l = length.to_bytes(4, byteorder="little")


    #concatenation
    hMAC = hMAC + iv + ct + l

    return hMAC, len(hMAC)

#Authenticate then decrypt
def decryption(confidkey, authkey, h_moR):

    #again for AES
    ck = hashlib.sha256(confidkey.encode('utf-8')).digest()
    ak = hashlib.sha256(authkey.encode('utf-8')).digest()

    #get the length of the final message that we received
    length = len(h_moR)

    size = h_moR[length - 4:length]

    hMac_sent = h_moR[0:32] #hmac that we received

    iv = h_moR[32:48] #IV received

    ct = h_moR[48:length - 4] #ciphertext received

    #generate our own hmac
    hMac_gen = hmac.new(key=ak, msg=ct, digestmod=hashlib.sha256).digest()

    #different digests! Fraud!
    if hmac.compare_digest(hMac_sent, hMac_gen) == False:
        print("Authentication failed.", flush=True)

    else:
        #Decryptor
        ciph2 = AES.new(ck, AES.MODE_CBC, iv)

        #decrypted but still bytes
        b_text = ciph2.decrypt(ct)

        try:
            #if unpad doesn't work then we have different confidentiality keys
            msg = unpad(b_text, 16)

            nugget = basicim_nugget_pb2.BasicIMNugget()
            nugget.ParseFromString(msg)

            print("%s: %s" % (nugget.nickname, nugget.message), flush=True)

        except:

            print("Confidentiality is compromised.", flush=True)


def main():

    signal.signal(signal.SIGINT, signal_handler)

    # connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect( (args.servername,9999) )

    read_fds = [ sys.stdin, s ]

    while True:
        (ready_list,_,_) = select.select(read_fds,[],[])
        if sys.stdin in ready_list:

            #CRTL D
            try:
                user_input = input()
            except EOFError:
                exit(0)
            if user_input.rstrip().lower() == "exit":
                s.close()
                exit(0)
            #final data sent
            h_mo, len_hmac = encryption(args.confidkey, args.authkey, user_input)
            s.send( struct.pack("!H", len_hmac ) )
            s.send( h_mo )

        if s in ready_list:
            packed_len = s.recv(2,socket.MSG_WAITALL)
            unpacked_len = struct.unpack("!H", packed_len )[0]
            h_moR = s.recv(unpacked_len,socket.MSG_WAITALL)
            decryption(args.confidkey, args.authkey, h_moR)

if __name__ == '__main__':
    main()
    
