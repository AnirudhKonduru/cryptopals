#!/usr/bin/env python3

import base64
from itertools import cycle
import pathlib
from Crypto.Cipher import AES

datadir = pathlib.Path(__file__).parent.parent.joinpath("data")


def challenge1(ip):
    b = bytes.fromhex(ip)
    return base64.b64encode(b).decode('utf-8')


def challenge2(s1, s2):
    sol = "%x" % (int(s1, 16) ^ int(s2, 16))
    return sol


# set a custom score for SPACE for better results
letter_frequencies = {"a": 11.682, "b": 4.434, "c": 5.238, "d": 3.174,
                      "e": 2.799, "f": 4.027, "g": 1.642, "h": 4.200,
                      "i": 7.294, "j": 0.511, "k": 0.456, "l": 2.415,
                      "m": 3.826, "n ": 2.284, "o": 7.631, "p": 4.319,
                      "q": 0.222, "r": 2.826, "s": 6.686, "t": 15.978,
                      "u": 1.183, "v": 0.824, "w": 5.497, "x": 0.045,
                      "y": 0.763, "z": 0.045, " ": 25}


def get_text_score(bytes_str):
    score = 0
    for c in bytes_str:
        score += letter_frequencies.get(chr(c).lower(), 0)
    return score


def xor_bytes(bytes_str, key):
    res = [x ^ y for x, y in zip(bytes_str, cycle(key))]
    # res = [a^b"x" for a in bytes_str]
    return bytes(res)


def find_best_single_letter_key(bytes_str):
    best = (0, "-", 0)
    for i in range(256):
        xor_result = xor_bytes(bytes_str, bytes([i]))
        score = get_text_score(xor_result)
        if score > best[0]:
            best = (score, xor_result, chr(i))
    return best


def challenge3(hex_input):
    bytes_input = bytes.fromhex(hex_input)
    return find_best_single_letter_key(bytes_input)[1]


def challenge4():
    # wget https://cryptopals.com/static/challenge-data/4.txt
    with open(datadir.joinpath("4.txt")) as f:
        lines = [line.rstrip('\n') for line in f]
    best = (0, 0, 0)
    for line in lines:
        line_bytes = bytes.fromhex(line)
        best_for_line = find_best_single_letter_key(line_bytes)
        if best_for_line[0] > best[0]:
            best = best_for_line
    return best[1]


def challenge5(ip_text):
    return xor_bytes(bytes(ip_text, 'utf-8'), b'ICE').hex()


def hamming_distance(bytes1, bytes2):
    if not len(bytes1) == len(bytes2):
        raise Exception("input params not of equal len")
    dist = bin(int(bytes1.hex(), 16) ^ int(bytes2.hex(), 16)).count('1')
    return dist


def challenge6():
    # wget https://cryptopals.com/static/challenge-data/6.txt
    with open(datadir.joinpath("6.txt")) as f:
        cipher_bytes = base64.b64decode(f.read())

    # get candidate key_size(s) with minimum hamming distances between blocks
    candidate_key_sizes = []
    for key_size in range(2, 40):
        dist = hamming_distance(
            cipher_bytes[:key_size], cipher_bytes[key_size:key_size*2])
        candidate_key_sizes.append((dist, key_size))

    candidate_solutions = []
    # try the top 10
    for d in sorted(candidate_key_sizes)[0:10]:
        key_size = d[0]
        cipher_blocks = [cipher_bytes[i:i+key_size]
                         for i in range(0, len(cipher_bytes), key_size)]

        # transpose cipher blocks so that each block is rotated by the same key
        transposed_blocks = []
        for i in range(key_size):
            transposed_block = [r for r in (b[i] if len(
                b) > i else None for b in cipher_blocks) if r is not None]
            transposed_blocks.append(transposed_block)

        # find single_char_key for each transposed block, concat them
        key_stream = ""
        for block in transposed_blocks:
            best_key = find_best_single_letter_key(block)
            key_stream += best_key[2]
            # print(best_key)
        # decipher the whole cipher block with the newly discovered candidate key
        deciphered_bytes = xor_bytes(cipher_bytes, bytes(key_stream, 'utf-8'))
        candidate_solutions.append((key_stream, deciphered_bytes))

    return candidate_solutions


def transpose(mat: list):
    return [*zip(*mat)]


def aes_decrypt_block(cipher_block: bytes, key: bytes):
    init_state = transpose(
        [tuple(cipher_block[i:i+4]) for i in range(0, 16, 4)])
    key_matrix = transpose([tuple(key[i:i+4])for i in range(0, 16, 4)])


def aes_decrypt(cipher: bytes, key: bytes):
    block_size = len(key)
    cipher_blocks = [cipher[i:i+block_size]
                     for i in range(0, len(cipher), block_size)]
    return b''.join([aes_decrypt_block(block, key) for block in cipher_blocks])


def challenge7():
    # wget https://cryptopals.com/static/challenge-data/7.txt
    with open(datadir.joinpath("7.txt")) as f:
        cipher_bytes = base64.b64decode(f.read())
    key = b"YELLOW SUBMARINE"
    res = AES.new(key, AES.MODE_ECB).decrypt(cipher_bytes)
    return res


def challenge8():
    # wget https://cryptopals.com/static/challenge-data/8.txt
    with open(datadir.joinpath("8.txt")) as f:
        lines_hex = [line.rstrip('\n') for line in f]
    lines = [bytes.fromhex(line) for line in lines_hex]
    repeat_counts = []
    for i, line in enumerate(lines):
        for key_length in range(4, 40):
            blocks = [line[i:i+key_length]
                      for i in range(0, len(line), key_length)]
            if (len(blocks) != len(set(blocks))):
                num_repeat_blocks = len(blocks) - len(set(blocks))
                repeat_counts.append({
                    "line_number": i,
                    "key_length": key_length,
                    "num_repeat_blocks": num_repeat_blocks
                })
    max_val = max(repeat_counts, key=lambda p: p["key_length"])
    print(max_val)
    return max_val["line_number"]
