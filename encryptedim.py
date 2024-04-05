import argparse, sys, select
import socket
#encryption part
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PORT = 9999

def encryption(confkey, authkey, msg):
    
    # hash confkey and authkey to 32 bytes
    hasher = SHA256.new()
    hasher.update(confkey.encode("utf8"))
    confkey = hasher.digest()
    hasher.update(authkey.encode("utf8"))
    authkey = hasher.digest()

    length = str(len(msg)).encode()
    # truncate the message into size no greater than 16 bytes
    if len(msg) > 15:
        curr_msg = msg[:15]
        more_msg = msg[15:]
    else:
        curr_msg = msg
        more_msg = "" #remaining of message for next chuck of encryption
  
    # initialization vector of 16 bytes
    iv = Random.get_random_bytes(16)

    # encryption with AES-256 in CBC mode
    cipher = AES.new(confkey, AES.MODE_CBC, iv)

    # padding to make length equals 16 bytes
    encrypt_length = cipher.encrypt(pad(length, 16))
    encrypt_msg = cipher.encrypt(pad(curr_msg.encode(), 16))

    # creating 32 bytes HMACs using SHA256 
    hmac_encrypt_length = HMAC.new(authkey, digestmod=SHA256).update(iv + encrypt_length).digest()
    hmac_encrypt_msg = HMAC.new(authkey, digestmod=SHA256).update(encrypt_msg).digest()
    # total size of encryption : 16 + 16 + 32 + 16 + 32 = 112 byte
    return iv + encrypt_length + hmac_encrypt_length + encrypt_msg + hmac_encrypt_msg, more_msg

def decryption(confkey, authkey, msg):  

     # hash confkey and authkey to 32 bytes
    hasher = SHA256.new()
    hasher.update(confkey.encode("utf8"))
    confkey = hasher.digest()
    hasher.update(authkey.encode("utf8"))
    authkey = hasher.digest()


    # decomposing encrypted data
    iv = msg[:16] #16 bytes
    
    encrypt_length = msg[16:16*2] #16 bytes
    hmac_encrypt_length = msg[16*2:16*2 + 32] #32 bytes
    
    encrypt_msg = msg[16*2 + 32:16*3 + 32] #16 bytes
    hmac_encrypt_msg = msg[16*3 + 32:16*3 + 32*2] #32 bytes
    
    # verifying HMACs
    hmac_length = HMAC.new(authkey, digestmod=SHA256).update(iv + encrypt_length)
    try:
        hmac_length.verify(hmac_encrypt_length)
    except ValueError:
        sys.stdout.write("ERROR: HMAC verification failed\n")
        sys.exit(1)
   
    hmac_msg = HMAC.new(authkey, digestmod=SHA256).update(encrypt_msg)
    try:
        hmac_msg.verify(hmac_encrypt_msg)
    except ValueError:
        sys.stdout.write("ERROR: HMAC verification failed\n")
        sys.exit(1)

    # decryption
    cipher = AES.new(confkey, AES.MODE_CBC, iv)
    # decrypt and unpadding
    decrypt_length = unpad(cipher.decrypt(encrypt_length), 16)
    decrypt_msg    = unpad(cipher.decrypt(encrypt_msg), 16)
    # return plain text
    return decrypt_msg.decode()

def run_server():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #reset the address
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('', PORT))
    listen_socket.listen()
    client_sockets = []

    while True:
        read_list = [listen_socket] + client_sockets + [sys.stdin]
        ready_read, _, _ = select.select(read_list, [], [])

        for sock in ready_read:
            if sock is listen_socket: #accept new connection
                new_conn, addr = sock.accept()
                client_sockets.append(new_conn)
            elif sock is sys.stdin: #write to network
                input = sys.stdin.readline()
                # print("writing")
                if not input:
                    listen_socket.close()
                    for c in client_sockets:
                        c.close()
                    return
                encrypted_input, more_msg = encryption(confkey, authkey, input)
                for c in client_sockets:
                    c.sendall(encrypted_input)

                while more_msg != "":
                    remaining_part, more_msg = encryption(confkey, authkey, more_msg)
                    for c in client_sockets:
                        c.sendall(remaining_part)

            else: #read from network
                msg = sock.recv(112) #receiving one chuck of 112 byte
                if msg:
                    # print("reading")
                    decrypted_msg = decryption(confkey, authkey, msg)
                    sys.stdout.write(decrypted_msg)
                    sys.stdout.flush()
                else:
                    client_sockets.remove(sock)
                    sock.close()

def run_client(hostname):
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((hostname, PORT))

    while True:
        input_list = [conn_sock, sys.stdin]
        ready_read, _, _ = select.select(input_list, [], [])

        for sock in ready_read:
            if sock is conn_sock: #read from network
                msg = sock.recv(112) #receiving one chuck of 112 byte
                if msg:
                    decrypted_msg = decryption(confkey, authkey, msg)
                    sys.stdout.write(decrypted_msg)
                    sys.stdout.flush()
                else:
                    conn_sock.close()
                    return
            elif sock is sys.stdin: #write to network
                input = sys.stdin.readline()
                if not input:
                    conn_sock.close()
                    return
                encrypted_input, more_msg = encryption(confkey, authkey, input)
                conn_sock.sendall(encrypted_input)
                while more_msg != "":
                    remaining_part, more_msg = encryption(confkey, authkey, more_msg)
                    conn_sock.sendall(remaining_part)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', '--s', action='store_true')
    parser.add_argument('--client', '--c')
    parser.add_argument("--confkey", dest="confkey", required=True)
    parser.add_argument("--authkey", dest="authkey", required=True)

    args = parser.parse_args()

    global confkey, authkey
    confkey = args.confkey
    authkey = args.authkey

    if args.server:
        run_server()
    elif args.client:
        if not args.client:
            raise Exception("--c flag requires a hostname argument")
        else:
            run_client(args.client)

if __name__ == '__main__':
    main()
