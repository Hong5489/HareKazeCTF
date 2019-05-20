#!/usr/bin/python3
import random
import binascii
import re
# from keys import flag
import codecs

# flag = re.findall(r'HarekazeCTF{(.+)}', flag)[0]
flag = 'ea5929e97ef77806bb43ec303f304673de19f7e68eddc347f3373ee4c0b662bc37764f74cbb8bb9219e7b5dbc59ca4a42018'
flag = codecs.decode(flag,"hex")
# print(flag)

def pad25(s):
    if len(s) % 25 == 0:
        return b''
    return b'\x25'*(25 - len(s) % 25)

def kinoko(text):
    text = text + pad25(text)
    mat = []
    for i in range(0, len(text), 25):
        mat.append([
            [text[i], text[i+1], text[i+2], text[i+3], text[i+4]],
            [text[i+5], text[i+6], text[i+7], text[i+8], text[i+9]],
            [text[i+10], text[i+11], text[i+12], text[i+13], text[i+14]],
            [text[i+15], text[i+16], text[i+17], text[i+18], text[i+19]],
            [text[i+20], text[i+21], text[i+22], text[i+23], text[i+24]],
            ])
    return mat

def takenoko(X, Y):
    W = [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]]
    for i in range(5):
        for j in range(5):
            for k in range(5):
                W[i][j] = (W[i][j] + X[i][k] * Y[k][j]) % 251
    return W

def encrypt(m1, m2):
    c = b""
    for mat in m1:
        mk = takenoko(mat, m2)
        for k in mk:
            c += bytes(k)

    return c


if __name__ == '__main__':
    m1 = kinoko(flag)
    m2 = [[126,30,87,79,144], [211,89,125,223,84], [213,149,47,130,121], [227,123,23,97,126], [9,202,123,220,59]]
    
    
    print("Encrypted Flag:")
    enc_flag = encrypt(m1, m2)
    print(enc_flag)
