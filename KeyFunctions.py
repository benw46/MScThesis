from ivs import *
from TxFunctions import *
from AdditionalFunctions import *
import binascii


def get_key_details(priv_key):
    print("Private Key: " + str(priv_key.to_wif()))
    print("Private Key Int: " + str(priv_key.to_int()))
    print("Public Key: " + str(binascii.hexlify(priv_key.public_key)))
    print("Address: " + priv_key.address)
    print("UTXO: " + str(priv_key.get_unspents()))
    print("Value of UTXO: " + str(priv_key.get_balance('bsv')))
    print("Address Balance: " + str(priv_key.get_balance('bsv')))
    print("")