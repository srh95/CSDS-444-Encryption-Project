import math

# Table to store amounts to rotate
rotatations = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

# initial a, b, c, and d values
initial_vals = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

functions = 16 * [lambda b, c, d: (b & c) | (~b & d)] + \
            16 * [lambda b, c, d: (d & b) | (~d & c)] + \
            16 * [lambda b, c, d: b ^ c ^ d] + \
            16 * [lambda b, c, d: c ^ (b | ~d)]

index_functions = 16 * [lambda i: i] + \
                  16 * [lambda i: (5 * i + 1) % 16] + \
                  16 * [lambda i: (3 * i + 5) % 16] + \
                  16 * [lambda i: (7 * i) % 16]


# Helper function to perform a left rotation
def left_rotation(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


# Function to perform encryption on the message
def encrypt(plaintext):
    plaintext = bytearray(plaintext)
    bit_length = (8 * len(plaintext)) & 0xffffffffffffffff
    plaintext.append(0x80)
    while len(plaintext) % 64 != 56:
        plaintext.append(0)
    plaintext += bit_length.to_bytes(8, byteorder='little')

    hash_pieces = initial_vals[:]

    for offset in range(0, len(plaintext), 64):
        a, b, c, d = hash_pieces
        # add padding to chunk of message so length is 64 less than a multiple of 512
        chunk = plaintext[offset:offset + 64]
        # loop to run four rounds of operations on chunk
        for i in range(64):
            func = functions[i](b, c, d)
            index_func = index_functions[i](i)
            to_rotate = a + func + constants[i] + int.from_bytes(chunk[4 * index_func:4 * index_func + 4], byteorder='little')
            new_b = (b + left_rotation(to_rotate, rotatations[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    return sum(x << (32 * i) for i, x in enumerate(hash_pieces))


def to_hex(output):
    result = output.to_bytes(16, byteorder='little')
    # format output to hexadecimal
    return '{:032x}'.format(int.from_bytes(result, byteorder='big'))
