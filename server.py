""" Server module for the chat application. """
# pylint: disable=invalid-name

import socket
import threading
import json
from hashlib import shake_256

from chat_cryptography import ChatCryptography, NetworkSecurityError


class Server:
    """ Server class for the chat application. """

    def __init__(self, host: str = "127.0.0.1", port: int = 9001, bufsize: int = 10240) -> None:
        self.host = host
        self.port = port
        self.bufsize = bufsize
        self.clients = []
        self.username_lookup = {}
        self.clients_public_keys = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.server_crypto = None

    def start(self):
        """ Start the server. """
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        self.server_crypto = ChatCryptography()

        while True:
            username = None
            c, addr = self.s.accept()
            print("|SERVER| Someone tries to connect")

            try:
                # send public key to the client
                c.send(json.dumps(self.server_crypto.public_key).encode())

                # receive the client's public key that was encrypted with the server's public key
                client_public_key = json.loads(self.receive_message(c))

                # get clients username
                username = self.receive_message(c)

                # add the client to the list of clients
                self.username_lookup[c] = username
                self.clients.append(c)
                self.clients_public_keys[c] = client_public_key

                # inform all clients that a new client has joined
                print(f"|SERVER| {username} has connected")
                self.broadcast(f'|SERVER| New person has joined: {username}', from_client=c)

                threading.Thread(target=self.handle_client, args=(c, addr,)).start()
            except Exception as err:
                print(f"|SERVER| {username} has encountered an error {err}")

    def broadcast(self, message: str, from_client: socket = None):
        """ Broadcast a message to all clients. """
        for client in self.clients:
            if client != from_client:
                self.send_message(message, client)

    def disconnect(self, c: socket, err: Exception = None):
        """ Disconnect a client. """
        username = self.username_lookup.get(c, 'Unknown')
        c.close()

        if c in self.clients:
            self.clients.remove(c)
        if username in self.username_lookup:
            del self.username_lookup[username]

        print(f"|SERVER| {username} has disconnected ({err})")
        self.broadcast(f'|SERVER| {username} has left the chat')

    def send_message(self, message: str, client: socket):
        """ Send a message to a client. """
        # encrypt the message with the clients public key
        message_encrypted = {
            "hash": shake_256(message.encode()).hexdigest(5),
            "hash_signed": self.server_crypto.sign_message(
                shake_256(message.encode()).hexdigest(5)
            ),
            "message_encrypted": self.server_crypto.encrypt(
                message,
                **self.clients_public_keys[client]
            )
        }

        client.send(json.dumps(message_encrypted).encode())

    def receive_message(self, c: socket):
        """ Receive a message from a client. """
        message = c.recv(self.bufsize).decode()
        message = json.loads(message)

        message_decrypted = self.server_crypto.decrypt(message["message_encrypted"])
        message_hash = shake_256(message_decrypted.encode()).hexdigest(5)

        if self.clients_public_keys.get(c):
            # verify the message hash by checking the signature
            hash_signed = self.server_crypto.verify_message_signature(message["hash_signed"],
                                                                      **self.clients_public_keys[c])
        else:
            # if the client has not sent a public key yet, we can't verify the signature
            # so we just accept the message and check the ordinary hash
            hash_signed = message_hash

        if (message_hash != hash_signed) or (message_hash != message["hash"]):
            # if the hash is not the same as the hash signed,
            # or the hash is not the same as the hash sent,
            # the message is not valid
            raise NetworkSecurityError(
                "Message hash (or hash signed) does not match. Possible tampering."
            )

        return message_decrypted

    def handle_client(self, c: socket, addr):
        """ Handle a client. """
        try:
            while True:
                message = self.receive_message(c)
                self.broadcast(message, from_client=c)
        except NetworkSecurityError as err:
            print(f"|SERVER| {self.username_lookup.get(c)} - {err}")
            self.send_message(
                "|SERVER SECURITY| Your message hash that server has received does not match. \
Possible tampering. The message was not sent to other clients.", c)
            # self.disconnect(c, err)
        except Exception as err:
            self.disconnect(c, err)


if __name__ == "__main__":
    s = Server("127.0.0.1", 9001)
    s.start()
