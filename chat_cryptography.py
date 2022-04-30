""" Module for cryptography of chat. """

import random


class ChatCryptography:
    """ Class for cryptography of chat. """

    def __init__(self, bits: int = 10):
        self.short_primes = self.generate_all_prime_numbers_up_to_x()
        self.__keys = self.generate_rsa_keys(bits)

    @classmethod
    def gcd(cls, a, b):
        """ Finds greatest common divisor by Euclidean algorithm """
        while b:
            a, b = b, a % b
        return a

    @classmethod
    def is_prime_simple(cls, number):
        """ Simple primality test. Works only for small numbers and is very slow """
        if number == 1:
            return False
        if number == 2:
            return True
        if number % 2 == 0:
            return False
        for i in range(3, int(number ** 0.5) + 1, 2):
            if number % i == 0:
                return False
        return True

    def is_prime_by_short_primes(self, number):
        """ Checks if number is prime by short primes.
        Doesn't work accurately, but is faster than miller-rabin test """
        for prime in self.short_primes:
            if number % prime == 0:
                return False
        return True

    def generate_all_prime_numbers_up_to_x(self, x: int = 500):
        """ Generates prime numbers up to x """
        return [i for i in range(1, x) if self.is_prime_simple(i)]

    @classmethod
    def random_number_with_n_bits(cls, n: int):
        """ Generates a random number with n bits """
        return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)

    @classmethod
    def miller_rabin_test(cls, number: int, number_of_iterations: int = 25):
        """ Miller-Rabin test for primality """
        if number == 2:
            return True
        if number % 2 == 0:
            return False
        d = number - 1
        s = 0
        while d % 2 == 0:
            d = d // 2
            s = s + 1
        for _ in range(number_of_iterations):
            x = pow(random.randrange(2, number - 1), d, number)
            if x not in (1, number - 1):
                for _ in range(1, s):
                    x = pow(x, 2, number)
                    if x == 1:
                        return False
                    if x == number - 1:
                        break
                else:
                    return False
        return True

    def generate_prime_number_with_n_bits(self, bits: int):
        """ Generates a prime number with n bits """
        while True:
            number = self.random_number_with_n_bits(bits)  # generate a random number
            if self.is_prime_by_short_primes(number) and self.miller_rabin_test(number):
                return number

    def generate_rsa_keys(self, bits: int):
        """ Generates RSA keys """
        p = self.generate_prime_number_with_n_bits(bits)
        q = self.generate_prime_number_with_n_bits(bits)

        phi = (p - 1) * (q - 1)
        e = self.generate_relatively_prime(phi)

        return {
            "n": p * q,  # n = p * q
            "e": e,  # gcd(e, (p - 1) * (q - 1)) == 1
            "d": pow(e, -1, phi)  # d = e^-1 mod phi
        }

    def generate_relatively_prime(self, phi: int) -> int:
        """ Finds relatively prime numbers """
        for i in range(2, phi):
            if self.gcd(i, phi) == 1:  # if i and phi are relatively prime
                return i
        raise Exception("Relatively prime numbers were not found")

    def encrypt(self, message: str, e: int = None, n: int = None):
        """ Encrypts message with RSA """
        e = e or self.__keys["e"]
        n = n or self.__keys["n"]
        return [pow(ord(char), e, n) for char in message]

    def decrypt(self, encrypted_message: list, d: int = None, n: int = None):
        """ Decrypts message with RSA """
        d = d or self.__keys["d"]
        n = n or self.__keys["n"]
        return "".join([chr(pow(char, d, n)) for char in encrypted_message])

    def sign_message(self, message: str, d: int = None, n: int = None):
        """ Signs message with RSA """
        d = d or self.__keys["d"]
        n = n or self.__keys["n"]
        return [pow(ord(char), d, n) for char in message]

    def verify_message_signature(self, signed_message: list, e: int = None, n: int = None):
        """ Verifies message signature with RSA """
        e = e or self.__keys["e"]
        n = n or self.__keys["n"]
        return "".join([chr(pow(char, e, n)) for char in signed_message])

    @property
    def public_key(self):
        """ Returns public key """
        return {"n": self.__keys["n"], "e": self.__keys["e"]}


if __name__ == '__main__':
    NUMBER_OF_BITS = 512
    c = ChatCryptography()
    print(c.generate_prime_number_with_n_bits(NUMBER_OF_BITS))
    print(c.generate_rsa_keys(NUMBER_OF_BITS))

    test_message = "Hello world!"
    print(f"Message: {test_message}")
    test_encrypted_message = c.encrypt(test_message)
    print(f"Encrypted message: {test_encrypted_message}")
    test_decrypted_message = c.decrypt(test_encrypted_message)
    print(f"Decrypted message: {test_decrypted_message}")
