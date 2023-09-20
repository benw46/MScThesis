#--------------------------------------------------------------------------------------------------
# --- Instance Variables Transaction ---
VERSION_1 = 0x01.to_bytes(4, byteorder='little')
SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
LOCK_TIME = 0x00.to_bytes(4, byteorder='little')

# BitcoinSV fork ID.
SIGHASH_FORKID = 0x40.to_bytes(4, byteorder='little')
# SIGHASH_ALL flag used below
HASH_TYPE = 0x41.to_bytes(4, byteorder='little')

# Opcodes
OP_0 = b'\x00'
OP_1 = b'\x51'
OP_2 = b'\x52'
OP_3 = b'\x53'
OP_FALSE = b'\00'
OP_CHECKSIG = b'\xac'
OP_DUP = b'v'
OP_VERIFY = b'\x69'
OP_EQUAL = b'\x87'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'
OP_HASH256 = b'\xaa'
OP_PUSH_20 = b'\x14'
OP_RETURN = b'\x6a'
OP_PUSHDATA1 = b'\x4c'
OP_PUSHDATA2 = b'\x4d'
OP_PUSHDATA4 = b'\x4e'
OP_TOALTSTACK = b'\x6b'
OP_DROP = b'\x75'
OP_SWAP = b'\x7c'
OP_ROT = b'\x7b'
OP_ADD = b'\x93'
OP_NUMEQUALVERIFY = b'\x9d'
OP_IF = b'\x63'
OP_ELSE = b'\x67'
OP_ENDIF = b'\x68'

#--------------------------------------------------------------------------------------------------
# --- Instance Variables ECDSA ---
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
#--------------------------------------------------------------------------------------------------