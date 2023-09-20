import docker
import time
import requests
import json


def docker_restart():
    container_name = "p2p-headers"
    client = docker.from_env()
    print("Spinning up " + container_name + "...")
    print("")
    container = client.containers.get(container_name)
    container.restart()
    print("Please wait for container to initialize...")
    time.sleep(20)
    print("Please wait for container to initialize...")
    time.sleep(20)
    print("Please wait for container to initialize...")
    time.sleep(20)
    print("")
    print("Container up!")
    print("")
    access_token = get_access_token()
    print("Initialized access token: " + access_token)
    print("")


def get_access_token():
    header = {"Authorization": "Bearer admin_only_afUMlv5iiDgQtj22O9n5fADeSb"}
    r = requests.post('http://localhost:8080/api/v1/access', headers=header)
    response_dict = json.loads(r.text)
    access_token = (response_dict['token'])
    return access_token


def get_header_by_height(height):
    access_token = get_access_token()
    header = {"Authorization": "Bearer " + str(access_token)}
    r = requests.get('http://localhost:8080/api/v1/chain/header/byHeight?height=' + height, headers=header)
    response_dict = json.loads(r.text[1:-1])
    print("")
    print("Hash: " + str(response_dict['hash']))
    print("Version: " + str(response_dict['version']))
    print("Prev Block Hash: " + str(response_dict['prevBlockHash']))
    print("Merkle Root: " + str(response_dict['merkleRoot']))
    print("Timestamp: " + str(response_dict['creationTimestamp']))
    print("Difficulty: " + str(response_dict['difficultyTarget']))
    print("Nonce: " + str(response_dict['nonce']))
    print("Work: " + str(response_dict['work']))


def get_tip():
    access_token = get_access_token()
    header = {"Authorization": "Bearer " + str(access_token)}
    r = requests.get('http://localhost:8080/api/v1/chain/tip', headers=header)
    response_dict = json.loads(r.text)
    print("Height of chain tip: " + str(response_dict['height']))


def get_root_by_hash(hash):
    access_token = get_access_token()
    header = {"Authorization": "Bearer " + str(access_token)}
    r = requests.get('http://localhost:8080/api/v1/chain/header/' + hash, headers=header)
    response_dict = json.loads(r.text)
    """
    print("Hash: " + str(response_dict['hash']))
    print("Version: " + str(response_dict['version']))
    print("Prev Block Hash: " + str(response_dict['prevBlockHash']))
    print("Merkle Root: " + str(response_dict['merkleRoot']))
    print("Timestamp: " + str(response_dict['creationTimestamp']))
    print("Difficulty: " + str(response_dict['difficultyTarget']))
    print("Nonce: " + str(response_dict['nonce']))
    print("Work: " + str(response_dict['work']))
    """
    return str(response_dict['merkleRoot'])