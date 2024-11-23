# P2P Encryption System (Server & Client)

This project implements a simple Peer-to-Peer (P2P) communication system with encryption and authentication for the cybersecurity program. It allows a client and a server to communicate securely by encrypting the messages using AES-256 encryption in CBC mode, and authenticating the message integrity with HMAC (SHA256).

## Features

Peer-to-Peer Communication: Server and client can communicate with each other using TCP sockets.
AES-256 Encryption: Messages are encrypted using AES-256 with CBC mode.
HMAC Authentication: Message integrity is ensured by HMAC-SHA256.
Message Chunking: Large messages are divided into smaller chunks for transmission.



## Setup and Usage

Command-Line Arguments

`--server (--s)`: Runs the program as the server.
`--client <hostname> (--c <hostname>)`: Runs the program as the client and connects to the server at the specified hostname.
`--confkey <key>`: The configuration key used for AES encryption. This key should be 32 bytes long (e.g., 256-bit).
`--authkey <key>`: The authentication key used for HMAC. This key should also be 32 bytes long.

### Running the Server
To run the server, use the following command:
```
python p2p_encryption.py --server --confkey <confkey> --authkey <authkey>
```
### Running the Client
To run the client, use the following command:
```
python p2p_encryption.py --client <server_ip> --confkey <confkey> --authkey <authkey>
```
- Replace <server_ip> with the IP address or hostname of the server.
- Replace <confkey> and <authkey> with the respective encryption and authentication keys.

## Encryption Details

- AES-256 (CBC Mode): The configuration key (confkey) and authentication key (authkey) are used to derive 256-bit keys, which are used for AES encryption in CBC (Cipher Block Chaining) mode.
- HMAC: SHA256-based HMAC is used to authenticate both the message length and the message content.
- Message Chunking: If the message exceeds 15 bytes, it is chunked into parts and each chunk is encrypted separately.

# Diploma
<!-- <object data="http://yoursite.com/the.pdf" type="application/pdf" width="700px" height="700px">
    <embed src="http://yoursite.com/the.pdf">
        <p>This browser does not support PDFs. Please download the PDF to view it: <a href="http://yoursite.com/the.pdf">Download PDF</a>.</p>
    </embed>
</object> -->
<img src = "./certificate.png">

