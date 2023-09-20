import hashlib
import binascii
import math


# Merkle Functions for Transactions
# Adapted from https://github.com/CyberGX/MerkleRootCalculator/blob/master/MerkleRootCalculator.py
# ------------------------------------------------------------------
def hash_pair_tx(first_tx_hash, second_tx_hash):
    # Reverse inputs before and after hashing
    # due to big-endian
    unhex_reverse_first = binascii.unhexlify(first_tx_hash)[::-1]
    unhex_reverse_second = binascii.unhexlify(second_tx_hash)[::-1]

    concat_inputs = unhex_reverse_first+unhex_reverse_second
    first_hash_inputs = hashlib.sha256(concat_inputs).digest()
    final_hash_inputs = hashlib.sha256(first_hash_inputs).digest()
    # reverse final hash and hex result
    return binascii.hexlify(final_hash_inputs[::-1])


 # Hash pairs of items recursively until a single value is obtained
def calc_merkle_root_tx(hashList):
    if len(hashList) == 1:
        return hashList[0]
    newHashList = []
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(hashList)-1, 2):
        newHashList.append(hash_pair_tx(hashList[i], hashList[i+1]))
    if len(hashList) % 2 == 1: # odd, hash last item twice
        newHashList.append(hash_pair_tx(hashList[-1], hashList[-1]))
    return calc_merkle_root_tx(newHashList)


def get_merkle_root_tx(hashList):
    merkle_root = calc_merkle_root_tx(hashList)
    return merkle_root


# Merkle Functions for Data
# ------------------------------------------------------------------
def hash_pair_data(first_hash, second_hash):
    concat_inputs = first_hash + second_hash
    hash_inputs = hashlib.sha256(concat_inputs).digest()
    return hash_inputs


def calc_merkle_root_data(hashList):
    if len(hashList) == 1:
        return hashList[0]
    newHashList = []
    # Process pairs. For odd length, the last is skipped
    for i in range(0, len(hashList)-1, 2):
        newHashList.append(hash_pair_data(hashList[i], hashList[i+1]))
    if len(hashList) % 2 == 1: # odd, hash last item twice
        newHashList.append(hash_pair_data(hashList[-1], hashList[-1]))
    return calc_merkle_root_data(newHashList)


def merkle_proof(index, hash_list):
    to_hash = []
    num_items = 8 # Hardcoded for this project
    # Add partner to list
    hash_group_0 = []
    if(index % 2 == 0):
        to_hash.append(hash_list[index + 1])
        hash_group_0.append(hash_list[index + 1])
    else:
        to_hash.append(hash_list[index - 1])
        hash_group_0.append(hash_list[index - 1])
    
    # Add quarter to list
    hash_group_1 = []
    for i in range(int(num_items / 4), 0, -1):
        i = i -1
        temp = (i % (num_items / 2) + (math.floor(index / 2) * 2))
        temp = (num_items / 2) - temp + ((math.floor((math.floor(index / 4) + 7) / 8) * 8) - 1)
        to_hash.append(hash_list[int(temp)])
        hash_group_1.append(hash_list[int(temp)])
    
    # Add half to list
    hash_group_2 = []
    for i in range(int(num_items / 2), 0, -1):
        i = i - 1
        temp = (i % (num_items / 2) + (math.floor(index / 4) * 4))
        temp = num_items - temp - 1
        to_hash.append(hash_list[int(temp)])
        hash_group_2.append(hash_list[int(temp)])
    
    return_list = []
    if(math.floor(index / 2) == 0):
        return_list.append(calc_merkle_root_data(hash_group_0))
        return_list.append(calc_merkle_root_data(hash_group_1))
        return_list.append(calc_merkle_root_data(hash_group_2))
    elif(math.floor(index / 2) == 1):
        return_list.append(calc_merkle_root_data(hash_group_1))
        return_list.append(calc_merkle_root_data(hash_group_0))
        return_list.append(calc_merkle_root_data(hash_group_2))
    elif(math.floor(index / 2) == 2):
        return_list.append(calc_merkle_root_data(hash_group_2))
        return_list.append(calc_merkle_root_data(hash_group_0))
        return_list.append(calc_merkle_root_data(hash_group_1))
    else:
        return_list.append(calc_merkle_root_data(hash_group_2))
        return_list.append(calc_merkle_root_data(hash_group_1))
        return_list.append(calc_merkle_root_data(hash_group_0))
    return return_list


def merkle_root_verify(item, item_index, hashes):
    item = hashlib.sha256(bytes(item, 'utf-8')).digest()
    hash_list = []
    num_items = 8
    # ---
    if(math.floor(item_index / (num_items / 4)) == 0):
        if(item_index % 2 == 0):
            hash_list.append(hash_pair_data(item, hashes[0]))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])
        if(item_index % 2 == 1):
            hash_list.append(hash_pair_data(hashes[0], item))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])
        temp1 = hash_pair_data(hash_list[0], hash_list[1])
        temp2 = hash_pair_data(temp1, hash_list[2])
    # ---         
    if(math.floor(item_index / (num_items / 4)) == 1):
        hash_list.append(hashes[0])
        hashes.remove(hashes[0])
        if(item_index % 2 == 0):
            hash_list.append(hash_pair_data(item, hashes[0]))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])  
        if(item_index % 2 == 1):
            hash_list.append(hash_pair_data(hashes[0], item))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])
        temp1 = hash_pair_data(hash_list[0], hash_list[1])
        temp2 = hash_pair_data(temp1, hash_list[2])
    # ---            
    if(math.floor(item_index / (num_items / 4)) == 2):
        hash_list.append(hashes[0])
        hashes.remove(hashes[0])
        if(item_index % 2 == 0):
            hash_list.append(hash_pair_data(item, hashes[0]))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])  
        if(item_index % 2 == 1):
            hash_list.append(hash_pair_data(hashes[0], item))
            hashes.remove(hashes[0])
            for i in range(0, len(hashes)):
                hash_list.append(hashes[i])
        temp1 = hash_pair_data(hash_list[1], hash_list[2])
        temp2 = hash_pair_data(hash_list[0], temp1)
    # ---            
    if(math.floor(item_index / (num_items / 4)) == 3):
        hash_list.append(hashes[0])
        hashes.remove(hashes[0])
        hash_list.append(hashes[0])
        hashes.remove(hashes[0])
        if(item_index % 2 == 0):
            temp = hash_pair_data(item, hashes[0])
            hash_list.append(temp)
        if(item_index % 2 == 1):
            hash_list.append(hash_pair_data(hashes[0], item))
        temp1 = hash_pair_data(hash_list[1], hash_list[2])
        temp2 = hash_pair_data(hash_list[0], temp1)
    return temp2