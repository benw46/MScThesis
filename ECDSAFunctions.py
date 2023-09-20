""" 
Functions in this file:
    get_len # UNUSED
    bin_exp # UNUSED
    mod_inv # UNUSED
    point_add # UNUSED
    point_mul # UNUSED
    ecdsa_sig # DEPRECATED
    ecdsa_ver # UNUSED
"""


import binascii
import random
import hashlib
from ivs import *


# Below values used for debugging
#k = 10889843155625828987231074820905732842100406053996880314707012829934128164520
#k = 95767065241997359022833318333328082392977722871275913377248423566531119865561
#k = 26236419474160683919830441100772883911114815145856300635907640656909474632122
#k = 94200393693582381558710637592052993967160308134706869816318976957301224342785
k = random.randint(1, n - 1)


# Get length of hex values (i.e. 1 bytes per 2 hex chars)
def get_len(item):
    length = len(str(item))
    if((length % 2) == 1):
        length = length + 1
    else:
        pass
    return length


# Binary Exponentiation
def bin_exp(x, n, p):
    res = 1    
    x = x % p
    if (x == 0) :
        return 0
    while (n > 0) :
        # If y is odd, multiply
        # x with result
        if ((n & 1) == 1) :
            res = (res * x) % p
        # y must be even now
        n = n >> 1      # y = y/2
        x = (x * x) % p
    return res


# Modular Inverse
def mod_inv(x, p):
    # Use Fermat's little theorem (providing prime modulus)
    return bin_exp(x, p - 2, p)


# Point addition algorithm
def point_add(x1, y1, x2, y2, p):
    if((x1 == x2) and (y1 == y2)):
        numerator = (3 * (x1 * x1)) % p
        denominator = mod_inv(2 * y1, p)
    else:
        numerator = (y2 - y1)
        denominator = mod_inv(x2 - x1, p)
    
    lam = (numerator * denominator) % p
    
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    
    return x3, y3


# Point Multiplication algorithm
def point_mul(x, y, n, p):
    bits = bin(n)[2:]
    bits = bits[1:]
    
    sx = x
    sy = y
    
    rx = x
    ry = y
    
    for bit in bits:
        # Double
        rx, ry = point_add(rx, ry, rx, ry, p)
        if((int(bit) & 1) == 1):
            # Add
            rx, ry = point_add(rx, ry, sx, sy, p)
    return rx, ry


def ecdsa_sig(m, d):    
    # Non-canonical DER error resolved
    # Ephemeral keyspace must be as stated below
    k = random.randint(1, n - 1)
    
    # SHA256 hash message only once, it has already been SHA256 hashed one time
    m1 = hashlib.sha256()
    m1.update(m)
    hashed_message = m1.hexdigest()
    
    eph_point = point_mul(Gx, Gy, k, p)
    eph_point_x = eph_point[0]
    
    # Remember: below is mod n, not mod p
    s_temp = (int(hashed_message, 16) + (d * eph_point_x))
    
    s = (mod_inv(k, n) * (s_temp)) % n
    r = eph_point_x
    
    print("Signing Complete")
    print("Eph Point x: " + str(eph_point[0]))
    print("Eph point y: " + str(eph_point[1]))
    print(" ")
    print("R: " + str(r))
    print("S: " + str(s))
    
    """
    1. 0x30 indicates start of DER
    2. One byte to encode length of data
    3. 0x02 header byte indicating integer
    4. One byte to encode length of r
    5. The r value as big-endian integer
    6. 0x02 header byte to indicate integer
    7. One byte to include length of the following s value
    8. The s value as big-endian integer
    """
    
    # DER Format Code Begin
    #------------------------------------------------------------
    r_hex = "00"
    r_hex = r_hex + str(hex(r)[2:])
    s_hex = str(hex(s)[2:])
    
    serial_1 = "30"
    serial_2 = hex(int(((get_len(r_hex) / 2) + (get_len(s_hex) / 2) + 4)))[2:]
    serial_3 = "02"
    serial_4 = hex(int(get_len(hex(r)[2:]) / 2) + 1)[2:]
    serial_5 = "00" + hex(r)[2:]
    serial_6 = "02"
    serial_7 = hex(int(get_len(hex(r)[2:]) / 2))[2:]
    serial_8 = hex(s)[2:]
    
    sig = serial_1 + str(serial_2) + serial_3 + str(serial_4)
    sig = sig + str(serial_5) + serial_6 + str(serial_7) + str(serial_8)
    sig = sig + str(binascii.hexlify(HASH_TYPE))[2:4]
    
    sig = bytes.fromhex(sig)
    
    """
    print("_______________________________________")
    print(serial_1)
    print(" ")
    print(serial_2)
    print(" ")
    print(serial_3)
    print(" ")
    print(serial_4)
    print(" ")
    print(serial_5)
    print(" ")
    print(serial_6)
    print(" ")
    print(serial_7)
    print(" ")
    print(serial_8)
    print(" ")
    print("_______________________________________")
    """
    
    return sig
    #return eph_point, r, s
    
    
def ecdsa_ver(m, Q, r, s, eph_point):   
    m1 = hashlib.sha256()
    m1.update(m)
    hashed_message = m1.hexdigest()
    
    temp_p1 = mod_inv(s, n) * (int(hashed_message, 16))
    p1 = point_mul(Gx, Gy, temp_p1, p)
    
    temp_p2 = mod_inv(s, n) * r
    p2 = point_mul(Q[0], Q[1], temp_p2, p)
    
    p3 = point_add(p1[0], p1[1], p2[0], p2[1], p)
    
    if(p3[0] == eph_point[0] and
      p3[1] == eph_point[1]):
        print("Signature Valid")
        print("P3: " + str(p3))
        print("Eph: " + str(eph_point))
    else:
        print("Signature failed")