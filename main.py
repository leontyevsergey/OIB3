import pickle
import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def generate_symmetric_key():
    _encKey = os.urandom(32)
    return _encKey


def serialize_symmetric_key(_key, path='sym_key.txt'):
    with open(path, 'wb') as key_file:
        key_file.write(_key)


def deserialize_symmetric_key(path):
    with open(path, 'rb') as key_file:
        _key = key_file.read()
        return _key


def encrypt_text(_key, text: str):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(_key, nonce), mode=None)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(bytes(text, 'utf-8'))
    result = {'ciphrotext': encrypted_text, 'nonce': nonce}
    return result


def decrypt_text(encrypted_text, _key, nonce):
    cipher = Cipher(algorithms.ChaCha20(_key, nonce), mode=None)
    decrypter = cipher.decryptor()
    decrypted_text = decrypter.update(encrypted_text)
    return decrypted_text


def generate_asymmetric_keys():
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return keys


def serialize_public_key(public_key, path='public_key.pem'):
    with open(path, 'wb') as public_file:
        public_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo))


def serialize_private_key(private_key, path='private_key.pem'):
    with open(path, 'wb') as private_file:
        private_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                     encryption_algorithm=serialization.NoEncryption()))


def deserialize_public_key(path='public_key.pem'):
    with open(path, 'rb') as file_pem:
        public_bytes = file_pem.read()
        deserialized_public_key = load_pem_public_key(public_bytes)
    return deserialized_public_key


def deserialize_private_key(path='private_key.pem'):
    with open(path, 'rb') as file_pem:
        private_bytes = file_pem.read()
        deserialized_private_key = load_pem_private_key(private_bytes, password=None)
    return deserialized_private_key


def encrypt_symmetric_key(_key, public_key):
    encrypted_key = public_key.encrypt(_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                          algorithm=hashes.SHA256(), label=None))
    return encrypted_key


def decrypt_symmetric_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
    return decrypted_key


def keys_generator(path_sym: str = 'sym_key.txt',
                   path_public: str = 'public_key.pem',
                   path_private: str = 'private_key.pem') -> None:

    symmetric_key = generate_symmetric_key()

    keys = generate_asymmetric_keys()
    public_key = keys.public_key()
    private_key = keys

    symmetric_key = encrypt_symmetric_key(symmetric_key, public_key)

    serialize_symmetric_key(symmetric_key, path_sym)
    serialize_public_key(public_key, path_public)
    serialize_private_key(private_key, path_private)


def encrypt_data(path_initial: str = 'file.txt',
                 path_encrypted_text: str = 'encr_file.txt',
                 path_private: str = 'private_key.pem',
                 path_sym: str = 'sym_key.txt',
                 ) -> None:

    with open(path_sym, 'rb') as sym_file:
        symmetric_key = sym_file.read()
    with open(path_initial, 'rb') as text_file:
        initial_text = text_file.read()

    private_key = deserialize_private_key(path_private)

    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)

    encrypted_text = encrypt_text(symmetric_key, initial_text.decode('utf-8'))

    with open(path_encrypted_text, 'wb') as encr_file:
        pickle.dump(encrypted_text, encr_file)


def decrypt_data(path_encrypted_text: str = 'encr_file.txt',
                 path_private: str = 'private_key.pem',
                 path_encrypted_key: str = 'sym_key.txt',
                 path_decrypted_text: str = 'decr_file.txt') -> None:

    with open(path_encrypted_key, 'rb') as sym_key_file:
        symmetric_key = sym_key_file.read()
    with open(path_private, 'rb') as pem_in:
        private_bytes = pem_in.read()

    private_key = load_pem_private_key(private_bytes, password=None, )

    symmetric_key = decrypt_symmetric_key(symmetric_key, private_key)

    with open(path_encrypted_text, 'rb') as encrypt_file:
        encoded_text = pickle.load(encrypt_file)

    decrypted_text = decrypt_text(encoded_text['ciphrotext'], symmetric_key, encoded_text['nonce'])

    with open(path_decrypted_text, 'w') as dec:
        dec.write(decrypted_text.decode('UTF-8'))


settings = {}

parser = argparse.ArgumentParser(description="ChaCha20 hybrid cryptosystem")
parser.add_argument('-s', '--settings', type=str, help="Path to the settings of cryptosystem. Check "
                                                                    "settings.txt in project directory for changing "
                                                                    "parameters.")
parser.add_argument('-gen', '--generation', type=str, help='type \'do\' to start keys generation mode '
                                                                        'and null not to start')
parser.add_argument('-enc', '--encryption', type=str, help='type \'do\' to start encryption mode'
                                                                        ' and null not to start')
parser.add_argument('-dec', '--decryption', type=str, help='type \'do\' to start decryption mode'
                                                                        'and null not to start')

if __name__ == '__main__':
    args = parser.parse_args()

    if args.settings is not None:
        with open(args.settings) as settings_file:
            for line in settings_file:
                key, value = line.rstrip("\n").split(": ")
                settings[key] = value
    else:
        with open('settings.txt') as settings_file:
            for line in settings_file:
                key, value = line.rstrip("\n").split(": ")
                settings[key] = value
    print(settings)

    if args.generation is not None:
        if args.generation == 'do':
            keys_generator(settings['symmetric_key'], settings['public_key'],
                           settings['secret_key'])
        elif args.generation == 'null':
            print('Key generation - skipped...')
        else:
            print('Incorrect command at pos2')

    if args.encryption is not None:
        if args.encryption == 'do':
            encrypt_data(settings['initial_file'], settings['encrypted_file'], settings['secret_key'],
                         settings['symmetric_key'])
        elif args.encryption == 'null':
            print('Text encryption - skipped...')
        else:
            print('Incorrect command at pos3')

    if args.decryption is not None:
        if args.decryption == 'do':
            decrypt_data(settings['encrypted_file'], settings['secret_key'], settings['symmetric_key'],
                         settings['decrypted_file'])
        elif args.decryption == 'null':
            print('Text decryption - skipped...')
        else:
            print('Incorrect command at pos4')

    print('Done')


# python main.py -s C:\Users\User\PycharmProjects\OIB3\settings.txt
# python main.py -gen do
# python main.py -enc do
# python main.py -dec do
