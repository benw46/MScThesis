import requests
import json
import math
from MerkleFunctions import *


def setup_hashes_for_merkle_proof(block_hash):
    all_tx_in_block = []
    r = requests.get('https://api.whatsonchain.com/v1/bsv/main/block/hash/' + block_hash)
    response_dict = json.loads(r.text)
    # Get the number of transactions
    num_tx = response_dict['num_tx']
    # get up to 1000 tx
    for i in range(0, len(response_dict['tx'])):
        all_tx_in_block.append(response_dict['tx'][i])

    # get transactions from 101 onwards
    if(num_tx > 1000):
        page_counter = math.ceil(num_tx / 50000)
        for i in range(1, page_counter + 1):
            r = requests.get('https://api.whatsonchain.com/v1/bsv/main/block/hash/' + block_hash + '/page/' + str(i))
            response_dict = json.loads(r.text)
            for j in range(0, len(response_dict)):
                all_tx_in_block.append(response_dict[j])  
    return get_merkle_root_tx(all_tx_in_block)


def get_custom_script_details(txid):
    r = requests.get('https://api.whatsonchain.com/v1/bsv/main/tx/hash/' + txid)
    response_dict = json.loads(r.text)
    custom_script = response_dict['vout'][0]['scriptPubKey']['asm']
    amount = response_dict['vout'][0]['value']
    txindex = response_dict['vout'][0]['n']
    return custom_script, amount, txindex