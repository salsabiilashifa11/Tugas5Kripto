from sympy import randprime
import random
import math

# Extended Euclidean algorithm


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(
            lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

# calculate `modular inverse`


def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def check_coprime(a, b):
    return math.gcd(a, b) == 1


def generate_coprime(a):
    exc = []
    while True:
        current = random.choice([i for i in range(1, a-1) if i not in exc])
        exc.append(current)
        if (check_coprime(a, current)):
            return current


def elgamal_generate_key(nbits, path):
    p = randprime(pow(2, nbits-1)+1, pow(2, nbits)-1)
    g = random.randint(1, pow(10, 6))
    x = random.randint(1, pow(10, 6))
    y = (g**x) % p
    pub = (y, g, p)
    pri = (x, p)

    elgamal_save_key(y, g, p, x, path)
    return (pub, pri)


def elgamal_save_key(y, g, p, x, path):
    pubkey = "save/key/" + path + ".pub"
    prikey = "save/key/" + path + ".pri"

    with open(pubkey, "w") as f:
        f.write("y: %s\n" % y)
        f.write("g: %s\n" % g)
        f.write("p: %s" % p)
    f.close()

    with open(prikey, "w") as r:
        r.write("x: %s\n" % x)
        r.write("p: %s" % p)
    r.close()


def elgamal_dss_sign(x, p, g, m):
    k = generate_coprime(p-1)
    r = pow(g, k, p)
    temp = m - x*r
    s = (temp * (modinv(k, (p-1)))) % (p-1)
    return (m, r, s)


def elgamal_dss_verify(y, g, p, m, r, s):
    v1 = pow(y, r, p) % p * pow(r, s, p) % p
    print(v1)
    # m di sini didapat dari hasil encode message asli (bukan dari signature)
    v2 = pow(g, m, p)
    print(v2)
    return v1 == v2


def save_eof(m, r, s, fname):
    with open(fname, "a") as f:
        f.write("*** Begin of digital signature ****\n")
        f.write(str(m) + "." + str(r) + "." + str(s) + "\n")
        f.write("*** End of digital signature ****\n")
    f.close()


def save_nf(m, r, s, fname):
    with open(fname, "w") as f:
        f.write("*** Begin of digital signature ****\n")
        f.write(str(m) + "." + str(r) + "." + str(s) + "\n")
        f.write("*** End of digital signature ****\n")
    f.close()


def read_eof(path):
    m_text = ""
    r = ""
    s = ""
    signature = False
    f = open(path, "r")
    for line in f:
        if (not signature):
            if line == ("*** Begin of digital signature ****\n"):
                signature = True
            else:
                m_text += (line)
        else:
            content = line.rstrip().split('.')
            r = content[1]
            s = content[2]
            break
    return (m_text, r, s)


def read_nf(path_m, path_rs):
    m_text = read_m_separate(path_m)
    r, s = read_rs_separate(path_rs)
    return (m_text, r, s)


def read_m_separate(path):
    m_text = ""
    f = open(path, "r")
    for line in f:
        m_text += line
    return m_text


def read_rs_separate(path):
    r = ""
    s = ""
    signature = False
    f = open(path, "r")
    for line in f:
        if (not signature):
            if line == ("*** Begin of digital signature ****\n"):
                signature = True
        else:
            content = line.rstrip().split('.')
            r = content[1]
            s = content[2]
            break
    return (r, s)

    # ----------------------------------------------------------------------------------

    # def elgamal_save_enc(msg, fname):
    #     with open(fname, "w") as f:
    #         for cipher in msg:
    #             for element in cipher:
    #                 f.write("%s " % element)
    #             f.write("\n")
    #     f.close()

    # def elgamal_read_enc(fname):
    #     msg = []
    #     f = open(fname, "r")
    #     for line in f:
    #         content = line.rstrip().split()
    #         tup = (int(content[0]), int(content[1]))
    #         msg.append(tup)
    #     return msg

    # def elgamal_read_key(fname):
    #     f = open(fname, "r")
    #     if (fname[-3:] == "pri"):
    #         point_content = f.readline().rstrip().split()
    #         key = (int(point_content[0]), int(point_content[1]))
    #     else:  # pub
    #         point_content = f.readline().rstrip().split()
    #         key = (int(point_content[0]), int(
    #             point_content[1]), int(point_content[2]))
    #     return key

    # def elgamal_encrypt(plaintext, y, g, p):
    #     result = []
    #     for char in plaintext:
    #         k = random.randint(1, pow(10, 4))
    #         a = (g**k) % p
    #         b = (y**k * ord(char)) % p
    #         result.append((a, b))
    #     return result

    # def elgamal_decrypt(ciphertext, x, p):
    #     result = ""
    #     for tup in ciphertext:
    #         result += chr((tup[1] * (modinv(tup[0]**x, p))) % p)
    #     return result
