""" Server module for the chat application. """
# pylint: disable=invalid-name

import socket
import threading
import json

from chat_cryptography import ChatCryptography


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
            "hash": None,  # TODO: hash the message
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
        # TODO: check if the message hash is valid

        return message_decrypted

    def handle_client(self, c: socket, addr):
        """ Handle a client. """
        try:
            while True:
                message = self.receive_message(c)
                self.broadcast(message, from_client=c)
        except Exception as err:
            self.disconnect(c, err)


if __name__ == "__main__":
    s = Server("127.0.0.1", 9001)
    s.start()
