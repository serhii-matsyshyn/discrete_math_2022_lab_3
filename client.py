""" Client module for the client side of the chat application. """
# pylint: disable=invalid-name
import json
import socket
import threading

from chat_cryptography import ChatCryptography


class Client:
    """ Client class for the client side of the chat application. """

    def __init__(self, server_ip: str = "127.0.0.1", port: int = 9001, bufsize: int = 1024,
                 username: str = None) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username or input("Please enter your username: ")
        self.bufsize = bufsize
        self.s = None

        self.client_crypto = None
        self.server_public_key = None

    def init_connection(self):
        """ Initialize the connection to the server. """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as err:
            print(f"[client]: could not connect to server: {err}")
            return

        self.client_crypto = ChatCryptography()  # create own key pair
        self.server_public_key = json.loads(self.s.recv(self.bufsize).decode())
        self.send_message(json.dumps(self.client_crypto.public_key))
        self.send_message(self.username)

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """ Reads messages from the server and prints them to the console. """
        while True:
            message = json.loads(self.s.recv(self.bufsize).decode())

            # decrypt message with the secrete key
            message_decrypted = self.client_crypto.decrypt(message["message_encrypted"])

            # TODO: check if hash is correct

            print(message_decrypted)

    def send_message(self, message: str):
        """ Sends a message to the server. It is encrypted with the server_public_key. """
        message_dictionary = {
            "hash": None,  # TODO: hash the message
            "message_encrypted": self.client_crypto.encrypt(message, **self.server_public_key)
        }

        self.s.send(json.dumps(message_dictionary).encode())

    def write_handler(self):
        """ Reads messages from the console and sends them to the server. """
        while True:
            message = f"|MESSAGE| {self.username}: {input()}"
            self.send_message(message)


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001)
    cl.init_connection()
