""" Client module for the client side of the chat application. """
# pylint: disable=invalid-name

import socket
import threading


class Client:
    """ Client class for the client side of the chat application. """

    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.s = None

    def init_connection(self):
        """ Initialize the connection to the server. """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as err:
            print(f"[client]: could not connect to server: {err}")
            return

        self.s.send(self.username.encode())

        # create key pairs

        # exchange public keys

        # receive the encrypted secret key

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """ Reads messages from the server and prints them to the console. """
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secrete key

            # ...

            print(message)

    def write_handler(self):
        """ Reads messages from the console and sends them to the server. """
        while True:
            message = input()

            # encrypt message with the secrete key

            # ...

            self.s.send(message.encode())


if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
