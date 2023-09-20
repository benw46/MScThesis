import binascii
import hashlib
import requests
from bitsv.format import address_to_public_key_hash
from bitsv.utils import int_to_varint
from AdditionalFunctions import txid_from_raw_hex
from ivs import *


class TxIn: # Taken from BitSV
    __slots__ = ('script', 'script_len', 'txid', 'txindex', 'amount')

    def __init__(self, script, script_len, txid, txindex, amount):
        self.script = script
        self.script_len = script_len
        self.txid = txid
        self.txindex = txindex
        self.amount = amount

    def __eq__(self, other):
        return (self.script == other.script and
                self.script_len == other.script_len and
                self.txid == other.txid and
                self.txindex == other.txindex and
                self.amount == other.amount)

    def __repr__(self):
        return 'TxIn({}, {}, {}, {}, {})'.format(
            repr(self.script),
            repr(self.script_len),
            repr(self.txid),
            repr(self.txindex),
            repr(self.amount)
        )


def construct_output_block(output): # Taken from BitSV, amended
    pkh = address_to_public_key_hash(output[0])
    output_block = b''
    output_block = output_block + output[1].to_bytes(8, byteorder='little')
    
    custom_script_len = 0
    # Check for script  
    if(len(output) == 3):
        custom_script_arr = output[2]
        for code in custom_script_arr:
            custom_script_len = custom_script_len + len(binascii.hexlify(code))
        custom_script_len = custom_script_len / 2
    
    output_block = output_block + bytes.fromhex(str(hex(int(custom_script_len) + 25))[2:])
    if(len(output) == 3):
        custom_script_arr = output[2]
        for code in custom_script_arr:
            if(type(code) == str):
                output_block = output_block + code
            else:
                output_block = output_block + code
    
    output_block = output_block + OP_DUP + OP_HASH160 + bytes.fromhex('14')
    output_block = output_block + pkh + OP_EQUALVERIFY + OP_CHECKSIG
    
    return output_block


# Below function taken from bitsv untils.py 
def hex_to_bytes(hexed):
    if len(hexed) & 1:
        hexed = '0' + hexed
    return bytes.fromhex(hexed)


def message_setup(private_key, unspent, prev_input_arr, output):   
    message_hash_object = hashlib.sha256()
    
    # DER Version
    version = VERSION_1
    
    # DER Inputs
    tx_id = unspent.txid
    tx_index = unspent.txindex

    inputs_hash_object_1 = hashlib.sha256()
    inputs_hash_object_2 = hashlib.sha256()
    inputs_hash_object_1.update(tx_id)
    inputs_hash_object_1.update(tx_index)
    inputs_hash_object_2.update(inputs_hash_object_1.digest())
    hash_prev_outs = inputs_hash_object_2.digest()

    inputs_sequence_hash_object_1 = hashlib.sha256()
    inputs_sequence_hash_object_2 = hashlib.sha256()
    inputs_sequence_hash_object_1.update(SEQUENCE)
    inputs_sequence_hash_object_2.update(inputs_sequence_hash_object_1.digest())
    hash_sequence = inputs_sequence_hash_object_2.digest()

    scriptcode = b''
    scriptcode_len = 0

    for code in prev_input_arr:
        # Check for script
        if(isinstance(code, list)):
            scriptcode = scriptcode + code[0]
            scriptcode_len = scriptcode_len + code[1]
        else:
            scriptcode = scriptcode + code
            scriptcode_len = scriptcode_len + int(str(binascii.hexlify(int_to_varint(len(prev_input_arr[0]))))[2:-1])

    # Plus 25 for locking script size
    scriptcode_len = scriptcode_len + 25
    scriptcode_len = bytes.fromhex(str(hex(scriptcode_len))[2:])    
    scriptcode = scriptcode + private_key.scriptcode

    amount = unspent.amount

    # DER Outputs
    output_block = construct_output_block(output)

    output_block_hash_object_1 = hashlib.sha256()
    output_block_hash_object_2 = hashlib.sha256()
    output_block_hash_object_1.update(output_block)
    output_block_hash_object_2.update(output_block_hash_object_1.digest())
    hash_outputs = output_block_hash_object_2.digest()  
    
    message_hash_object.update(version)
    message_hash_object.update(hash_prev_outs)
    message_hash_object.update(hash_sequence)
    message_hash_object.update(tx_id)
    message_hash_object.update(tx_index)
    message_hash_object.update(scriptcode_len)
    message_hash_object.update(scriptcode)
    message_hash_object.update(amount)
    message_hash_object.update(SEQUENCE)
    message_hash_object.update(hash_outputs)
    message_hash_object.update(LOCK_TIME)
    message_hash_object.update(HASH_TYPE)
    message = message_hash_object.digest()
    
    """
    print("___________")
    print(binascii.hexlify(hash_prev_outs))
    print(binascii.hexlify(hash_sequence))
    print(binascii.hexlify(tx_id))
    print(binascii.hexlify(tx_index))
    print(binascii.hexlify(scriptcode_len))
    print(binascii.hexlify(scriptcode))
    print(binascii.hexlify(amount))
    print(binascii.hexlify(SEQUENCE))
    print(binascii.hexlify(hash_outputs))
    print(binascii.hexlify(LOCK_TIME))
    print(binascii.hexlify(HASH_TYPE))
    print(binascii.hexlify(message))
    print("___________")
    """
    
    return message


# Below transaction crafts scriptsig and locking script
def custom_transaction(private_key, unspents, input_arr, prev_input_arr, outputs):   
    inputs = [] # create array of inputs
    
    for unspent in unspents: # separates txid, txind and amount fields
        tx_id = hex_to_bytes(unspent.txid)[::-1] # not using to_bytes as txid is str not int
        tx_index = unspent.txindex.to_bytes(4, byteorder='little')
        amount = unspent.amount.to_bytes(8, byteorder='little')
        inputs.append(TxIn('', 0, tx_id, tx_index, amount))
    
    public_key = private_key.public_key
    public_key_len = len(public_key).to_bytes(1, byteorder='little')
    script_sig = b''
    
    # Scriptsig Format Begin 
    #------------------------------------------------------------
    for _input in inputs:
        script_sig_temp = b''
        
        message = message_setup(private_key, _input, prev_input_arr, outputs[0])
        #signature = ecdsa_sig(message, private_key.to_int()) # Deprecated custom ecdsa_sig()
        signature = private_key.sign(message)
        signature = signature + HASH_TYPE[:1] # Take first byte i.e. 0x41
        
        script_sig_temp = (len(signature)).to_bytes(1, byteorder='little')
        script_sig_temp = script_sig_temp + signature + public_key_len + public_key
        
        for code in input_arr:
            script_sig_temp = script_sig_temp + code
        
        script_sig_temp_len = 0
        script_sig_temp_len = int(len(script_sig_temp))
        script_sig_temp_len_hex = hex(script_sig_temp_len)
        
        script_sig_temp = bytes.fromhex(str(script_sig_temp_len_hex)[2:]) + script_sig_temp
        script_sig_temp = _input.txid + _input.txindex + script_sig_temp
        script_sig_temp = script_sig_temp + SEQUENCE
        script_sig = script_sig + script_sig_temp
        
    script_sig = VERSION_1 + bytes.fromhex('01') + script_sig # Hard-coded for one input
    
    #------------------------locking_script---------------------------
    output_count = len(outputs)
    locking_script = b'' + output_count.to_bytes(1, 'little')
    
    for output in outputs:
        amount = output[1]
        bytes_amount = amount.to_bytes(8, byteorder='little')
        
        pkh = address_to_public_key_hash(output[0])
        locking_script = locking_script + bytes_amount

        # Custom Script
        for output in outputs:
            if(len(output) == 3):
                custom_script_arr = output[2]

                custom_script_len = 0
                for code in custom_script_arr:
                    custom_script_len = custom_script_len + len(code)
                
                locking_script = locking_script + bytes.fromhex(str(hex(int(custom_script_len) + 25))[2:])

                for code in custom_script_arr:
                    if(type(code) == str):
                        locking_script = locking_script + code
                    else:
                        locking_script = locking_script + code
            else:
                locking_script = locking_script + bytes.fromhex('19')
        
        locking_script = locking_script + OP_DUP + OP_HASH160 + bytes.fromhex('14')
        locking_script = locking_script + pkh + OP_EQUALVERIFY + OP_CHECKSIG
        
    locking_script = locking_script + bytes.fromhex('00000000')
    #----------------------------------------------------------------
    
    script_sig = script_sig + locking_script

    raw_tx = binascii.hexlify(script_sig)
    raw_tx = str(raw_tx)[2:-1]

    my_obj = {"txhex": raw_tx}
    url = "https://api.whatsonchain.com/v1/bsv/main/tx/raw"
    r = requests.post(url, json=my_obj)

    if(r.status_code == 200):
        print("Transaction Sent " + txid_from_raw_hex(raw_tx) + " sent!")
        return txid_from_raw_hex(raw_tx)
    else:
        print("Error status: " + str(r.status_code))
