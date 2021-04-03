#!/usr/bin/env python3

from set1.set1 import *


def test_challenge1():
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert challenge1(input) == expected


def test_challenge2():
    s1 = "1c0111001f010100061a024b53535009181c"
    s2 = "686974207468652062756c6c277320657965"
    expected = "746865206b696420646f6e277420706c6179"
    result = challenge2(s1, s2)
    assert expected == result


def test_challenge3():
    ip = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    assert b"Cooking MC's like a pound of bacon" == challenge3(ip)


def test_challenge4():
    assert b'Now that the party is jumping\n' == challenge4()


def test_challenge5():
    ip = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"\
               "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert expected == challenge5(ip)


def test_challenge6():
    expected_key = "Terminator X: Bring the noise"
    candidate_solutions = challenge6()
    # check if if found the key
    assert expected_key in [c[0] for c in candidate_solutions]


def test_hamming_distance():
    b1 = b"this is a test"
    b2 = b"wokka wokka!!!"
    assert 37 == hamming_distance(b1, b2)


def test_challenge7():
    res: str = challenge7()
    assert res.startswith(b"I'm back and I'm ringin'")


def test_challenge8():
    assert challenge8() == 132
