from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from queue import Queue
from threading import Thread

class EncryptionWorker(Thread):
    def __init__(self, plaintext_queue, ciphertext_queue,userKey):
        Thread.__init__(self)
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue
        self.key = userKey.encode()
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def run(self):
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                break
            self.encrypt(plaintext)

    def encrypt(self, plaintext):
        nonce = self.cipher.nonce
        ciphertext, tag = self.cipher.encrypt_and_digest(pad(plaintext.encode(), AES.block_size))
        self.ciphertext_queue.put((ciphertext, tag, nonce))

    def decrypt(self, ciphertext, tag, nonce):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext.decode()

if __name__=='__main__':
    while(1):
        user_key = input("Enter a 16, 24, or 32 byte key: ")
        print(user_key)
        if len(user_key) not in [16, 24, 32]:
            print("Invalid key length. Key must be 16, 24, or 32 bytes long.")
        else:
            plaintext_queue = Queue()
            ciphertext_queue = Queue()
            worker = EncryptionWorker(plaintext_queue, ciphertext_queue, user_key)
            worker.start()
            break

    # Get input from user
    user_input = input("Enter a message to encrypt: ")
    plaintext_queue.put(user_input)
    plaintext_queue.put(None)  # Signal the worker to stop

    ciphertext, tag, nonce = ciphertext_queue.get()

    # Print the ciphered text
    print("Ciphered text: ", ciphertext.decode('latin-1'))

    # Decrypt and print the plaintext
    print("Decrypted text: ", worker.decrypt(ciphertext, tag, nonce))  # Should print the user's input

    worker.join()