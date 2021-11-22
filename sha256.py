'''
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380

credit : https://en.wikipedia.org/wiki/SHA-2
'''

# BLOCK_SIZE, DIGEST_SIZE, BITS_IN_WORD
from math import sqrt


BLOCK_SIZE = 64
DIGEST_SIZE = 32
BITS_WORD = 32

# Initialize hash values
H_ARR = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Initialize array of round constants
K_ARR = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def rotate_right(x: int, shift: int, size: int = BITS_WORD):
    '''
    ROTR n(x) =(x >> n) ∨ (x << w - n)
    '''
    return (x >> shift) | (x << size - shift)


def majority(x: int, y: int, z: int):
    '''
    Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    '''
    return (x & y) ^ (x & z) ^ (y & z)


def choose(x: int, y: int, z: int):
    '''
    Ch(x,y,z) = (x∧y)⊕(¬x∧z)
    '''
    return (x & y) ^ (~x & z)


def sigma0(x: int):
    '''
    ROTR 7(x) ⊕ ROTR 18(x) ⊕ SHR 3(x)
    '''
    return (
        rotate_right(x, 17) ^
        rotate_right(x, 19) ^
        (x >> 10)
    )


def sigma1(x: int):
    '''
    ROTR 17(x) ⊕ ROTR 19(x) ⊕ SHR 10(x)
    '''
    return (
        rotate_right(x, 17) ^
        rotate_right(x, 19) ^
        (x >> 10)
    )


def capitalized_sigma0(x: int):
    '''
    ROTR 2(x) ⊕ ROTR 13(x) ⊕ ROTR 22(x)
    '''
    return (
        rotate_right(x, 2) ^
        rotate_right(x, 13) ^
        rotate_right(x, 22)
    )


def capitalized_sigma1(x: int):
    '''
    ROTR 6(x) ⊕ ROTR 11(x) ⊕ ROTR 25(x)
    '''
    return (
        rotate_right(x, 6) ^
        rotate_right(x, 11) ^
        rotate_right(x, 25)
    )


def hash(message: bytearray) -> bytearray:
    '''
    input   : bytes, bytearray, or string
    output  : SHA-256 hash
    '''
    # converting message
    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    else:
        raise TypeError

    # Add padding
    msg_length = len(message) * 8
    message.append(0x80)

    while ((len(message) * 8 + 64) % 512 != 0):
        message.append(0x00)

    # big endian
    message += msg_length.to_bytes(8, 'big')

    # Parsing
    blocks = []
    for i in range(0, len(message), 64):
        blocks.append(message[i:i+64])

    # Initial hash value
    a = H_ARR[0]
    b = H_ARR[1]
    c = H_ARR[2]
    d = H_ARR[3]
    e = H_ARR[4]
    f = H_ARR[5]
    g = H_ARR[6]
    h = H_ARR[7]

    for block in blocks:
        msg_schedule = []
        for t in range(0, BLOCK_SIZE):
            if (t <= 15):
                msg_schedule.append(bytes(block[t*4:(t*4)+4]))
            else:
                term1 = sigma1(int.from_bytes(msg_schedule[t-2], 'big'))
                term2 = int.from_bytes(msg_schedule[t-7], 'big')
                term3 = sigma0(int.from_bytes(msg_schedule[t-15], 'big'))
                term4 = int.from_bytes(msg_schedule[t-16], 'big')

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) %
                            2**32).to_bytes(4, 'big')
                msg_schedule.append(schedule)

    # iterate t = 0-63
    for t in range(BLOCK_SIZE):
        t1 = ((h + capitalized_sigma1(e) + choose(e, f, g) + K_ARR[t] +
               int.from_bytes(msg_schedule[t], 'big')) % 2**32)

        t2 = (capitalized_sigma0(a) + majority(a, b, c)) % 2**32

        h = g
        g = f
        f = e
        e = (d + t1) % 2**32
        d = c
        c = b
        b = a
        a = (t1 + t2) % 2**32

    # Intermediate hash
    h0 = (H_ARR[0] + a) % 2**32
    h1 = (H_ARR[1] + b) % 2**32
    h2 = (H_ARR[2] + c) % 2**32
    h3 = (H_ARR[3] + d) % 2**32
    h4 = (H_ARR[4] + e) % 2**32
    h5 = (H_ARR[5] + f) % 2**32
    h6 = (H_ARR[6] + g) % 2**32
    h7 = (H_ARR[7] + h) % 2**32

    # Produce final hash value in big endian
    return (
        (h0).to_bytes(4, 'big') +
        (h1).to_bytes(4, 'big') +
        (h2).to_bytes(4, 'big') +
        (h3).to_bytes(4, 'big') +
        (h4).to_bytes(4, 'big') +
        (h5).to_bytes(4, 'big') +
        (h6).to_bytes(4, 'big') +
        (h7).to_bytes(4, 'big')
    )


def main():
    # print(int.from_bytes(hash("ini nyoba").hex().encode('utf8'), 'big'))
    message = 'inicoba'
    encoded = str(int.from_bytes(message.encode('utf8'), 'big'))
    byte = encoded.encode()
    # byte = message.encode('utf8')
    print(hash(byte).hex())
    print(hash(message).hex())
    # print(pow(2347, int.from_bytes(hash("ini nyoba").hex().encode('utf8'), 'big')))


if __name__ == '__main__':
    main()
