from elgamal import *
from sha256 import *


def main():
    message = 'aha'
    message_salah = 'aha'
    H = hash(message)
    H_salah = hash(message_salah)

    # public, private = elgamal_generate_key(16, '')
    public = (9450, 779716, 54443)
    private = (576245, 54443)
    signature = elgamal_dss_sign(
        private[0], private[1], public[1], int.from_bytes(H.hex().encode('utf8'), 'big'))

    print(signature)

    verify = elgamal_dss_verify(
        public[0], public[1], public[2], int.from_bytes(H_salah.hex().encode('utf8'), 'big'), signature[1], signature[2])

    print(verify)


if __name__ == '__main__':
    main()
