import hashlib
import binascii


def int2bytes(i, enc):
    return i.to_bytes((i.bit_length() + 7) // 8, enc)


def convert_hex(str, enc1, enc2):
    return int2bytes(int.from_bytes(bytes.fromhex(str), enc1), enc2).hex()


def flip_endi(string_to_flip):
    temp_str = ""
    for i in range(0, len(string_to_flip), 2):
        temp_str = temp_str + string_to_flip[len(string_to_flip) - 2 - i]
        temp_str = temp_str + string_to_flip[len(string_to_flip) - 1 - i]
    return temp_str


def hex_to_bytes(hexed):
    if len(hexed) & 1:
        hexed = '0' + hexed
    return bytes.fromhex(hexed)


def txid_from_raw_hex(raw_hex):
    m1 = hashlib.sha256()
    m2 = hashlib.sha256()
    
    m1.update(hex_to_bytes(raw_hex))
    m2.update(m1.digest())
    return flip_endi(binascii.hexlify(m2.digest()).decode("utf-8"))