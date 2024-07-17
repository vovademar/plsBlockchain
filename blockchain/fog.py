from collections import namedtuple
import secrets
from typing import Any, Dict
import flask
from hashlib import sha256
from dataclasses import dataclass
import requests
import yaml
import schedule

from cipher import AESCipher
from helpers.log import logger
from helpers.utils import sxor
from helpers.schedulebackground import run_continuously
from helpers.shuffleshifter import shuffle_shifter, unshuffle_shifter
from db.merkletree import MerkleTree
from db.bitmap import Bitmap
from db.block import Block, Contribution
from db.rot import RootOfTrust
from db.tunstalltree import TunstallTree
from db.cas import CAS

import codecs
from base64 import b64decode

app = flask.Flask(__name__)

# The list of enrolled UIDs
uids = []
uid_to_key = {}

cas = CAS()

contributions: list[Contribution] = []
current_contributions: list[Contribution] = []
last_stored_contribution: Contribution = None
last_stored_contribution_uid: str = None

def examine_prefix(content: str) -> bool:
    """
    Examine 2 bytes of the proof and check that no UID with this value has been enrolled

    If no UID with this value has been enrolled, return the false value

    If a UID with this value has been enrolled, return the true value
    """
    # Check if the prefix is in the list of known prefixes
    if content[:2] in uids:
        return True
    # If not, return False
    return False


def handle_enroll(message: Dict[str, Any]) -> bool:
    """
    :param message: message to be handled
    :return: True if the message is valid, False otherwise
    """
    # check that message type is 'proof'
    if message["type"] != "proof":
        return False

    # check that message contains a content field
    if "content" not in message:
        return False

    # check that the content does not start with a prefix
    if examine_prefix(message["content"]):
        return False

    # add the first two characters of the content to the list of ids
    uid = message["content"][:2]
    uids.append(uid)
    uid_to_key[uid] = message["key"]
    return True


def compute_nonce(q: str, key: str) -> int:
    """
    Q = P1 || Encrypt(P1 xor N*, key)

    Compute N* from Q

    Return N*
    """
    print(q, " - q")
    proof = q[:64]
    encrypted = q[64:]
    key = codecs.decode(key, 'hex_codec')
    decrypted = AESCipher(key).decrypt(encrypted, b"0000000000000000")
    n_star = sxor(proof, decrypted)
    return n_star


def handle_contribute(message: Dict[str, Any]) -> bool:
    """
    :param message: message to be handled
    :return: True if the message is valid, False otherwise
    """
    match message["type"]:
        case "proof":
            print(message, " - handle msg")
            user_id = message["content"][:2]
            content = message["content"][2:]
            ContributionWithPos = namedtuple(
                "ContributionWithPos", ["contribution", "pos"]
            )
            proof_contrpos = None

            print(contributions, " - all contributions in fog")

            # Find latest contribution with the same UID and with proof type, and remember its position in this list
            for i, contribution in enumerate(contributions):
                print(contribution.user_id, contribution.type, " expected user id: ", user_id)
                if contribution.user_id == user_id and contribution.type == "proof":
                    proof_contrpos = ContributionWithPos(contribution, i)
                    print(proof_contrpos, " - contribution with pos")

            failed = True
            N = None
            linkverify_contrpos = None
            # Start traversing list from position of the latest contribution with the same UID and with proof type
            for i, contribution in enumerate(contributions[proof_contrpos.pos :]):
                print(i, " - i  ", contribution, " - contribution")
                # Find linkverify contribution with the same UID
                if (
                    contribution.user_id == user_id
                    and contribution.type == "linkverify"
                ):
                    print("here with: ", contribution)
                    # Compute H(L xor content) != proof_contrpos.contribution.content
                    link = contribution.content[:64]
                    # print(link, " - link!!!")
                    print(sha256(sxor(link, content).encode()).hexdigest())
                    if (
                        sha256(sxor(link, content).encode()).hexdigest()
                        != proof_contrpos.contribution.content
                    ):
                        continue
                    N = sxor(link, content)
                    # If H(content || N) = V
                    verify = contribution.content[64:]
                    if sha256((content + N).encode()).hexdigest() == verify:
                        print("Found linkverify with correct verify")
                        failed = False
                        linkverify_contrpos = ContributionWithPos(contribution, i + proof_contrpos.pos)
                        print(linkverify_contrpos)
                        print("LV contrpos: " + str(linkverify_contrpos.pos))
                        break
            if failed:
                logger.info(
                    f"Invalid contribution from thing with UID {user_id}, possibly a jam-spoof attack"
                )
                return False
            for contribution in contributions[
                proof_contrpos.pos : linkverify_contrpos.pos + 1
            ]:
                if (
                    contribution.user_id == user_id
                    and contribution.type == "linkverify"
                ):
                    link = contribution.content[:64]
                    verify = contribution.content[64:]
                    if (
                        sha256(sxor(link, content).encode()).hexdigest()
                        == proof_contrpos.contribution.content
                    ):
                        return True
                    logger.info(
                        f"Invalid contribution from thing with UID {user_id}, possibly a jam-spoof attack"
                    )
            return False
        case "signature":
            return True
        case "linkverify":
            return True


@app.route("/enroll", methods=["POST"])
def enroll():
    message = flask.request.get_json()
    if not handle_enroll(message):
        return flask.jsonify({"type": "fail"})
    uid = message["content"][:2]
    logger.info(f"Enrolled thing with UID {uid}")
    contributions.append(Contribution(uid, message["type"], message["content"][:64]))
    print("contribution in enroll - ", Contribution(uid, message["type"], message["content"][:64]))
    current_contributions.append(Contribution(uid, message["type"], message["content"][:64]))
    n_star = compute_nonce(message["content"], uid_to_key[uid])
    print(uid_to_key[uid], " - uid to key")
    return flask.jsonify(
        {"type": "ack", "content": sha256(n_star.encode()).hexdigest()}
    )

def set_uid(uid):
    last_stored_contribution_uid = uid

def set_last_stored_contribution(contribution):
    last_stored_contribution = contribution



@app.route("/contribute", methods=["POST"])
def contribute():
    global last_stored_contribution
    global last_stored_contribution_uid

    message = flask.request.get_json()
    uid = message["content"][:2]
    last_stored_contribution = Contribution(uid, message["type"], message["content"])
    last_stored_contribution_uid = uid

    print(message, " - new msg")
    if not handle_contribute(message):
        return flask.jsonify({"type": "fail"})
    contributions.append(Contribution(uid, message["type"], message["content"][2:]))

    current_contributions.append(Contribution(uid, message["type"], message["content"][2:]))
    logger.info(
        f'Thing with UID {uid} contributed {message["type"]} with content {message["content"][2:]}'
    )
    return flask.jsonify({"type": "success"})



@app.route("/get_contributions", methods=["GET"])
def get_contributions():
    return flask.jsonify({"type": "success", "content": contributions})


@app.route("/get_contrhash", methods=["GET"])
def get_contrhash():
    # Return hash of latest contribution
    return flask.jsonify(
        {
            "type": "success",
            "content": sha256(str(contributions[-1]).encode()).hexdigest(),
        }
    )
    
@app.route("/get_latest_hash", methods=["GET"])
def get_latest_blockhash():
    # Return hash of latest block
    return flask.jsonify(
        {
            "type": "success",
            "content": cas.get_latest_block_root_hash(),
        }
    )
    
@app.route("/get_root_of_trust", methods=["GET"])
def get_root_of_trust():
    root_of_trust = cas.get_unverified_root_of_trust()
    if root_of_trust is None:
        return flask.jsonify({"type": "fail", "content": "No root of trust yet"})
    return flask.jsonify(
        {
            "type": "success",
            "content": {
                "block_id": root_of_trust.block_id,
                "root_hash": root_of_trust.root_hash,
                "total_number_of_users": root_of_trust.total_number_of_users,
                "users_in_block": root_of_trust.users_in_block,
                "flags": root_of_trust.flags.get_bitmap_str(),
                "users": root_of_trust.users,
                "redundancy": root_of_trust.redundancy.get_bitmap_str(),
            }
        }
    )

@app.route("/generate_key", methods=["GET"])
def generate_key():
    key = secrets.token_hex(16)
    return flask.jsonify({"type": "success", "content": key})

@app.route("/get_contribution", methods=["GET"])
def get_contribution():
    message = flask.request.get_json()
    block_id = message["block_id"]
    user_id = message["user_id"]
    contribution, path = cas.get_contribution(user_id, block_id)
    merkle_path = ""
    for sibling_hash, direction in path:
        merkle_path += f"{direction}: {sibling_hash.hex()}\n"
    json_contribution = {
        "user_id": contribution.user_id,
        "type": contribution.type,
        "content": contribution.content,
        "path": merkle_path,
    }
    return flask.jsonify({"type": "success", "content": json_contribution})

@app.route("/get_lp", methods=["GET"])
def get_lp():
    seq_host = config["sequencer"]["host"]
    seq_port = config["sequencer"]["port"]
    lp = requests.get(f"http://{seq_host}:{seq_port}/get_lp").json()
    lp_content = {
        "link": lp["content"]["link"],
        "proof": lp["content"]["proof"],
    }
    return flask.jsonify({"type": "success", "content": lp_content})

@app.route("/get_uids", methods=["GET"])
def get_uids():
    return flask.jsonify({"type": "success", "content": uids})

@app.route("/store_data", methods=["POST"])
def store_data():
    message = flask.request.get_json()
    data = message["content"]
    cas.add_data(data)
    print(data, " - stored data")
    lastBlock = cas.get_latest_block()

    return flask.jsonify({"type": "success", "content": data})


@app.route("/get_latest_block_data", methods=["GET"])
def get_latest_block_data():
    latest_block = cas.get_latest_block()
    print (latest_block, " - latest block!")
    # return flask.jsonify({"type": "success", "content": latest_block})


@app.route("/check_user_in_block", methods=["GET"])
def check_user_in_block():
    message = flask.request.get_json()
    block_id = message["block"]
    user_id = message["user"]

    all_blocks = cas.get_all_blocks()
    if all_blocks[int(block_id)].contributions != []:
        if all_blocks[int(block_id)].contributions[-1].user_id == user_id:
            return flask.jsonify({"type": "success", "content": all_blocks[int(block_id)].contributions[-1]})
        else:
            return flask.jsonify({"type": "success", "content": "no such user in block"})
    else:
        return flask.jsonify({"type": "success", "content": "contributions are empty"})


@app.route("/get_all_blocks", methods=["GET"])
def get_all():
    all_blocks = cas.get_all_blocks()
    print(all_blocks, " - all blocks")
    print(contributions, " - all contributions")


def check_last_contribution(user_id: str):
    print(last_stored_contribution_uid, " - lastuid")
    if last_stored_contribution_uid == user_id:
        return True
    return False

@app.route("/listen_user_contributions", methods=["GET"])
def listen_user_contributions():
    message = flask.request.get_json()
    user_id = message["user"]

    if check_last_contribution(user_id):
        return flask.jsonify({"type": "success", "content": last_stored_contribution})
    else:
        return flask.jsonify({"type": "success", "content": "user not found"})



@app.route("/get_data", methods=["GET"])
def get_data():
    message = flask.request.get_json()
    data_hash = message["content"]
    data = cas.get_data(data_hash)
    if data is None:
        return flask.jsonify({"type": "fail", "content": "Data not found"})
    return flask.jsonify({"type": "success", "content": data})

@app.route("/encrypt", methods=["POST"])
def encrypt_data():
    from base64 import b64encode, b64decode
    import codecs
    
    message = flask.request.get_json()
    xored = b64decode(message["xored"]).decode("utf-8")
    ivv = str.encode(message["ivv"])
    kkk = codecs.decode(message["kkk"], 'hex_codec')
    encrypted = AESCipher(kkk).encrypt(xored, ivv)
    return flask.jsonify({"type": "success", "content": encrypted})

@app.route("/decrypt", methods=["POST"])
def decrypt_data():
    import codecs
    
    message = flask.request.get_json()
    encrypted = message["encrypted"]
    ivv = str.encode(message["ivv"])
    kkk = codecs.decode(message["kkk"], 'hex_codec')
    decrypted = AESCipher(kkk).decrypt(encrypted, ivv)
    return flask.jsonify({"type": "success", "content": decrypted})

@app.route("/decrypt_simple", methods=["POST"])
def decrypt_data1():
    import codecs
    
    message = flask.request.get_json()
    encrypted = message["encrypted"]
    uid = message["uid"]
    kkk = message["kkk"]
    print("Signature received for decrypt = " + encrypted)
    print(uid_to_key[uid], " - uid_to_key")
    key = uid_to_key[uid]

    print(key, " - key")
    print("sha key - ", sha256(key.encode()).digest()[:16])

    kkk = codecs.decode(kkk, 'hex_codec')
    decrypted = AESCipher(kkk).decrypt(encrypted, sha256(key.encode()).digest()[:16])
    return flask.jsonify({"type": "success", "content": decrypted})


@app.route("/calculatehash", methods=["POST"])
def calculatehash():
    message = flask.request.get_json()
    p = message["proof"]
    s = message["sign"]
    
    xored = sxor(p, s)
    
    return flask.jsonify({"type": "success", "content": xored})

def create_block():
    global current_contributions
    if len(current_contributions) < 1:
        block_id = len(cas.blocks)
        empty_block = Block(block_id, None, [])
        cas.add_block(empty_block)
        logger.info(f"Created empty block with id {block_id}")
        return
    # Create Merkle Tree from the list of contributions
    leaves = []
    for contribution in current_contributions:
        leaves.append((contribution.user_id, contribution.content.encode()))
    merkle_tree = MerkleTree(leaves)
    merkle_root = merkle_tree.root_hash_str
        
    users_number = len(uids)
        
    current_contribution_uids = set([contribution.user_id for contribution in current_contributions])
        
    # Number of different users in contributions
    block_users_number = len(current_contribution_uids)
        
    id_hex_to_int = lambda id_hex: int(id_hex, 16)
        
    int_uids = list(map(id_hex_to_int, uids))
        
    # Find maximum uid in the list of uids
    max_uid = max(int_uids)
        
    # Create users bitmap
    users_bitmap = Bitmap(max_uid + 1)
        
    # Fill users in current contributions in users bitmap
    for uid in int_uids:
        users_bitmap.set(uid)
            
    flags = Bitmap(8)
    # type = compressed
    flags.set(7)
        
    # w = 8
    flags.set(5)

    redundancy = Bitmap(32)
        
    tunstall_tree = None
    
    block_id = len(cas.blocks)
        
    # If bitmap is set to be compressed
    if flags.test(7) and not flags.test(6):
        count_of_ones_in_bitmap = users_bitmap.get_bitmap_str().count("1")
            
        # p = count_of_ones_in_bitmap / max_uid
        p = 0.6
        if flags.test(5):
            w = 8
        else:
            w = 4
        tunstall_tree = TunstallTree(p, w)
        
        if False:
            # Convert users_bitmap str to int value and shuffle it
            users_bitmap_int = int(users_bitmap.get_bitmap_str(), 2)
            users_bitmap = shuffle_shifter(users_bitmap_int, block_id, 32)
            # Convert shuffled users_bitmap int to bit string
            users_bitmap = bin(users_bitmap)[2:]
            users_bitmap = users_bitmap.zfill(max_uid + 1)
            shuffled_users_bitmap = Bitmap(max_uid + 1)
            for i in range(len(users_bitmap)):
                if users_bitmap[i] == "1":
                    shuffled_users_bitmap.set(i)
            users_bitmap = shuffled_users_bitmap
        users_bitmap = tunstall_tree.encode(users_bitmap.get_bitmap_str())
        
    block = Block(block_id, merkle_tree, current_contributions)
    cas.add_block(block)
    logger.info(f"Block {block_id} with merkle root {block.merkle_tree.root_hash_str} created!")
    
    root_of_trust = RootOfTrust(block_id, merkle_root, users_number, block_users_number, flags, users_bitmap, redundancy)
    cas.add_unverified_root_of_trust(root_of_trust)

    current_contributions = []



def try_create_genesis_block():
    if len(cas.blocks) > 0:
        return
    genesis_block = Block(0, None, [])
    cas.add_block(genesis_block)
    logger.info("Created genesis block")
    
    
def load_blockchain():
    cas.load(config["fog"]["blockchain_path"])
    # Fill contributions and distinct uids from loaded CAS blocks
    for block in cas.blocks:
        for contribution in block.contributions:
            current_contributions.append(contribution)
            if contribution.user_id not in uids:
                uids.append(contribution.user_id)
            

if __name__ == "__main__":
    # read config yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    # load_blockchain()
    try_create_genesis_block()
    schedule.every(config["fog"]["block_creation_interval"]).seconds.do(create_block)
    stop_run_continuously = run_continuously()
    app.run(host='0.0.0.0', port=config["fog"]["port"])