from bitsv import PrivateKey
from KeyFunctions import *
from TxFunctions import *
from dockerInterface import *
from bitsv.network.meta import Unspent
from WoCInterface import *


#key1 = PrivateKey("REDACTED", network='main')
address = key1.address
exit = False
sent_txids = []
#sent_txids.append('')
merkle_proof_list = []


# below func needed to get around floating point errors
def mult_by_hundred_mil(value): 
    temp = (value * 10**8)
    frac, whole = math.modf(temp)
    string = (f'{frac:2.8f}')
    if(string == '1.00000000'):
        return math.ceil(temp)
    else:
        return math.floor(temp)


def craft_custom_transaction(data):
    data_str = str((binascii.hexlify(data)))[2:-1]
    data_len = (hex(int(len(data_str) / 2)))[2:]
    len_and_data = data_len + data_str
    len_and_data = bytes.fromhex(len_and_data)

    input_arr = []
    prev_input_arr = []
    output_arr = [len_and_data, OP_DROP]
    unspents = []
    outputs = []

    if(len(sent_txids) == 0): # use standard UTXO first
        unspents = key1.get_unspents()
        unspent_amount = unspents[0].amount
        outputs.append((address, unspent_amount - 500, output_arr))
    else: # use custom UTXO second
        txid = sent_txids[len(sent_txids) - 1]
        return_data = get_custom_script_details(txid)
        custom_script = return_data[0].split()
        for i in range(0, len(custom_script)):
            prev_input_arr.append(custom_script[i])

        # make data item into list with len
        temp_list = []
        len_data = int(len(prev_input_arr[0]) / 2)

        hex_str = prev_input_arr[0]
        len_str = (hex(int(len(hex_str) / 2))[2:])
        len_and_data_unspent = len_str + hex_str
        temp_list.append(bytes.fromhex(len_and_data_unspent))

        temp_list.append(len_data)
        prev_input_arr[0] = temp_list
        prev_input_arr.pop(2)
        prev_input_arr.pop(2)
        prev_input_arr.pop(2)
        prev_input_arr.pop(2)
        prev_input_arr.pop(2)

        prev_input_arr.append(globals()[prev_input_arr[1]])
        prev_input_arr.pop(1)

        amount = int(mult_by_hundred_mil(return_data[1])) # dont use (num * 10**8)
        txindex = return_data[2]
        
        unspents = []
        my_unspent = Unspent(amount, 0, txid, txindex)
        unspents.append(my_unspent) 
        outputs.append((address, amount - 500, output_arr))

    return_txid = custom_transaction(key1, unspents, input_arr, prev_input_arr, outputs)
    return return_txid


def get_merkle_root(block_hash):
    mr_temp = setup_hashes_for_merkle_proof(block_hash)
    mr_temp = str(mr_temp)[2:-1]
    return mr_temp


def parse_log_file():
    hashed_logs = []
    file = open("LogFile.txt", "r")
    while file:
        line = file.readline()
        if line == "":
            break
        log_return = []
        log = line.split()
        log[3] = log[3] + " " + log[4]
        log.remove(log[4])
        log[4] = log[4] + " " + log[5] + " " + log[6]
        log.remove(log[5])
        log.remove(log[5])
        for i in range(0, len(log)):
            log_return.append(hashlib.sha256(bytes(log[i], 'utf-8')).digest())
        hashed_logs.append(log_return)
    return hashed_logs


def generate_proof():
    log_num = input("Generate proof for log number: ") # choose log 4
    item_num = input("Generate proof for log number " + str(log_num) + " item: ") # choose item 3
    logs = parse_log_file()
    mp = merkle_proof(int(item_num), logs[int(log_num)])

    print("Proof for log " + log_num + ", item " + item_num + ".")   
    for i in range(0, len(mp)):
        merkle_proof_list.append(binascii.hexlify(mp[i]))
        print(merkle_proof_list[i])
    return mp


#--------------------------main function-----------------------------
def main():
    hashed_logs = []
    merkle_roots = []

    while(not exit):
        print("")
        command = input("Command: ")
        if(command == 'exit'):
            break
        elif(command == 'get key details'):
            get_key_details(key1)
        elif(command == 'restart docker'):
            docker_restart()
        elif(command == 'get header by height'):
            get_header_by_height()
        elif(command == 'get chain tip'):
            get_tip()
        if(command == 'load logs'):
            print("Loading Logs...")
            counter = 0
            parsed_logs = parse_log_file() # Parse log into list structure, sha256 them
            for i in range(0, len(parsed_logs)):
                hashed_logs.append(parsed_logs[i])
                counter = counter + 1
            print(str(counter) + " log/s loaded.")
        if(command == 'print logs'):
            if(len(hashed_logs) == 0):
                print("No logs loaded.")
            else:
                for i in range(0, len(hashed_logs)):
                    print("Log " + str(i + 1) + ":")
                    for j in range(0, len(hashed_logs[i])):
                        print(binascii.hexlify(hashed_logs[i][j]))
                    print("")
        if(command == 'merkalize logs'):
            if(len(hashed_logs) == 0):
                print("No logs loaded.")
                break
            else:
                print("Merkalizing Logs...")
                for i in range(0, len(hashed_logs)):
                    merkle_roots.append(calc_merkle_root_data(hashed_logs[i]))
                    counter = counter + 1
                print(str(len(merkle_roots)) + " merkle roots computed.")
                print("")
                print("Storing merkle roots on blockchain...")
                for i in range(0, len(merkle_roots)):
                    data_temp = str(binascii.hexlify(merkle_roots[i]))[2:-1]
                    data = bytes.fromhex(data_temp)
                    return_txid = craft_custom_transaction(data)
                    sent_txids.append(return_txid)
        if(command == 'print merkle roots'):
            if(len(merkle_roots) == 0):
                print("No merkle roots computed.")
            else:
                for i in range(0, len(merkle_roots)):
                    print("Merkle root " + str(i + 1) + ":")
                    print(binascii.hexlify(merkle_roots[i]))
        if(command == 'generate proof'):
            mp = generate_proof()
        if(command == 'print merkle proof'):
            if(len(merkle_proof_list) == 0):
                print("No merkle proof generated yet.")
            else:
                print("Merkle proof:")
                for i in range(0, len(merkle_proof_list)):
                    print(merkle_proof_list[i])
        if(command == 'audit logs'):
            if(len(merkle_proof_list) == 0):
                print("There must have been a merkle proof generated to audit a log.")
            else:
                print("An auditor would like to check if log #4 was generated at the timestamp [06/Apr/2023:07:52:01 -0500].")
                print("The auditor requests a merkle proof. Luckily, we have a proof for log number 4, item 3, as shown above.")
                print("The auditor will calculate the merkle proof independently...")
                mrv = merkle_root_verify('[06/Apr/2023:07:52:01 -0500]', 3, mp)
                print("Auditor's root: " + str(binascii.hexlify(mrv)))
                print("True root: " + str(binascii.hexlify(calc_merkle_root_data(hashed_logs[int(4)]))))
        if(command == 'print sent transactions'):
            print("Sent transactions (txids): ")
            for i in range(0, len(sent_txids)):
                print(sent_txids[i])
        if(command == 'confirm sent transactions'):
            print("The software would like to verify that transaction")
            print(sent_txids[0] + " has been confirmed.")
            print("To do this, we'll find what block this transaction is in and verify that block's merkle root.")
            print("Txid: " + sent_txids[0])

            url = "https://api.whatsonchain.com/v1/bsv/main/tx/hash/" + str(sent_txids[0])
            r = requests.get(url)
            response_dict = json.loads(r.text)
            bh = response_dict['blockhash']
            print("Blockhash: " + bh)
            pulse_root = get_root_by_hash(bh)
            print("Merkle root from Pulse: " + pulse_root)

            url = "https://api.whatsonchain.com/v1/bsv/main/block/hash/" + bh
            r = requests.get(url)
            response_dict = json.loads(r.text)
            mr_from_node = response_dict['merkleroot']
            print("Merkle root from node:  " + mr_from_node)


#--------------------------main instantiation-----------------------------
main()
