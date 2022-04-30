""" Server module for the chat application. """
# pylint: disable=invalid-name

import socket
import threading


class Server:
    """ Server class for the chat application. """

    def __init__(self, host: str = "127.0.0.1", port: int = 9001) -> None:
        self.host = host
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        """ Start the server. """
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate keys ...

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"|SERVER| {username} tries to connect")

            try:
                self.broadcast(f'|SERVER| New person has joined: {username}')
                self.username_lookup[c] = username
                self.clients.append(c)

                # send public key to the client

                # ...

                # encrypt the secret with the clients public key

                # ...

                # send the encrypted secret to a client

                # ...

                threading.Thread(target=self.handle_client, args=(c, addr,)).start()
            except Exception as err:
                print(f"|SERVER| {username} has encountered an error {err}")

    def broadcast(self, msg: str):
        """ Broadcast a message to all clients. """
        for client in self.clients:
            # encrypt the message

            # ...

            client.send(msg.encode())

    def disconnect(self, c: socket, err: Exception = None):
        """ Disconnect a client. """
        username = self.username_lookup.get(c, 'Unknown')
        c.close()

        if c in self.clients:
            self.clients.remove(c)
        if username in self.username_lookup:
            del self.username_lookup[username]

        self.broadcast(f'|SERVER| {username} has left the chat')
        print(f"|SERVER| {username} has disconnected ({err})")

    def handle_client(self, c: socket, addr):
        """ Handle a client. """

        try:
            while True:
                msg = c.recv(1024)

                for client in self.clients:
                    if client != c:
                        client.send(msg)
        except Exception as err:
            self.disconnect(c, err)


if __name__ == "__main__":
    s = Server("127.0.0.1", 9001)
    s.start()
