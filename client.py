""" Client module for the client side of the chat application. """
# pylint: disable=invalid-name
import json
import socket
import threading
from hashlib import shake_256

from chat_cryptography import ChatCryptography, NetworkSecurityError


class Client:
    """ Client class for the client side of the chat application. """

    def __init__(self, server_ip: str = "127.0.0.1", port: int = 9001, bufsize: int = 10240,
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

            self.client_crypto = ChatCryptography()  # create own key pair
            self.server_public_key = json.loads(self.s.recv(self.bufsize).decode())
            self.send_message(json.dumps(self.client_crypto.public_key))
            self.send_message(self.username)
        except json.JSONDecodeError:
            print(f"|CLIENT ERROR| Buffer size is too small, increase it to receive messages correctly")
            return
        except Exception as err:
            print(f"|CLIENT ERROR| Could not connect to server: {err}")
            return

        message_handler = threading.Thread(target=self.read_handler, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler, args=())
        input_handler.start()

    def read_handler(self):
        """ Reads messages from the server and prints them to the console. """
        while True:
            try:
                message = json.loads(self.s.recv(self.bufsize).decode())

                # decrypt message with the secrete key
                message_decrypted = self.client_crypto.decrypt(message["message_encrypted"])
                hash_signed = self.client_crypto.verify_message_signature(message["hash_signed"],
                                                                          **self.server_public_key)

                message_hash = shake_256(message_decrypted.encode()).hexdigest(5)
                if (message_hash != hash_signed) or (message_hash != message["hash"]):
                    raise NetworkSecurityError(
                        "Message hash that you received does not match. Possible tampering."
                    )

                print(message_decrypted)
            except NetworkSecurityError as err:
                print(f"|CLIENT SECURITY|: {err}")
                print("|CLIENT SECURITY|: Message hidden because of this error...")
            except (json.JSONDecodeError, TypeError):
                print("|CLIENT ERROR| Buffer size is too small, increase it to receive messages correctly")
                print("Closing connection...")
                self.s.close()
                break
            except Exception as err:
                print(f"|CLIENT ERROR| Error while reading from server: {err}")
                print("Closing connection...")
                self.s.close()
                break

    def send_message(self, message: str):
        """ Sends a message to the server. It is encrypted with the server_public_key. """
        message_dictionary = {
            "hash": shake_256(message.encode()).hexdigest(5),
            "hash_signed": self.client_crypto.sign_message(
                shake_256(message.encode()).hexdigest(5)
            ),
            "message_encrypted": self.client_crypto.encrypt(message, **self.server_public_key)
        }

        self.s.send(json.dumps(message_dictionary).encode())

    def write_handler(self):
        """ Reads messages from the console and sends them to the server. """
        while True:
            message = f"|MESSAGE| {self.username}: {input()}"
            self.send_message(message)


if __name__ == "__main__":
    cl = Client(server_ip="127.0.0.1", port=9001, bufsize=10240)
    cl.init_connection()
