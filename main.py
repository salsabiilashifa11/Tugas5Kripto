from elgamal import *
from sha256 import *


def main():
    message = 'ini buat nyoba'
    H = hash(message)

    public, private = elgamal_generate_key(16, '')

    signature = elgamal_dss_sign(
        private[0], private[1], public[1], int.from_bytes(H.hex().encode('utf8'), 'big'))

    print(signature)

    verify = elgamal_dss_verify(
        public[0], public[1], public[2], signature[0], signature[1], signature[2])

    print(verify)


if __name__ == '__main__':
    main()
