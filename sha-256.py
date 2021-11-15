
'''
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
Note 3: The compression function uses 8 working variables, a through h
Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    and when parsing message block data from bytes to words, for example,
    the first word of the input message "abc" after padding is 0x61626380

credit : https://en.wikipedia.org/wiki/SHA-2
'''
# Initialize hash values
H_arr = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Initialize array of round constants
K_arr = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Preprocessing
def add_padding(message):
    '''
    begin with the original message of length L bits
    append a single '1' bit
    append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
    append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    such that the bits in the message are L 1 00..<K 0's>..00 <L as 64 bit integer> = k*512 total bits
    '''
    message_length = len(message)
    
    # append '1' bit
    message += "80".decode('hex_codec')
    
    # create a 64-entry message schedule array w[0..63] of 32-bit
    blocks = (message_length + 1 + 8 + (64-1)) // 64
    req_length = blocks * 64
    padding = req_length - message_length - 1 - 8

    # append '0' padding
    message = padding * '00'.decode('hex_codec')
    message = ('%016X' % (message_length * 8)).decode('hex_codec')

    return

def main():
    tesMsg = ('ini coba add padding'.decode('hex_codec')).encode('hex_codec')
    # msg = hex(tesMsg)
    print(add_padding(tesMsg))

if __name__ == '__main__':
    main()