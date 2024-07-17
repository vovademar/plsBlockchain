import codecs
import json
import time
from collections import namedtuple
from hashlib import sha256
from random import randint
from typing import Any, Dict

import requests
import schedule
import yaml

from cipher import AESCipher
from db.block import Contribution
from db.rot import RootOfTrust
from db.tunstalltree import TunstallTree
from helpers.schedulebackground import run_continuously
from helpers.utils import sxor

contributions: list[Contribution] = []
contributions1: list[Contribution] = []
contributions2: list[Contribution] = []


class Thing:
    def __init__(self, config):
        self.config = config
        self.key = ""
        self.uid = ""
        self.nonce_star = ""
        self.latest_proof = None
        self.latest_nonce = ""
        self.prev_latest_nonce = ""
        self.l = ""

        self.skip = True
        self.is_enrolled = False

        self.link = None
        self.signature = None
        self.proof = None

        self.prev_link = None
        self.prev_signature = None
        self.prev_proof = None

        self.host = config["fog"]["host"]
        self.port = config["fog"]["port"]

        self.roots_of_trust: list[RootOfTrust] = []
        self.blockchain_users = []
        self.checked_rots = {}

    def enroll(self):
        response = requests.get(f"http://{self.host}:{self.port}/generate_key").json()
        lp = requests.get(f"http://{self.host}:{self.port}/get_lp").json()
        uids_json = requests.get(f"http://{self.host}:{self.port}/get_uids").json()["content"]
        print("UIDS JSON ", uids_json)
        # self.blockchain_users = json.loads(uids_json)

        self.link = lp["content"]["link"]
        self.proof = lp["content"]["proof"]

        if response["type"] == "fail":
            return False

        self.key: str = response["content"]

        nonce = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )
        self.nonce_star = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )
        self.prev_latest_nonce = str(nonce)

        proof = sha256(self.prev_latest_nonce.encode()).hexdigest()
        xored = sxor(proof, self.nonce_star)
        ivv = "0123456789abcdef".encode()
        kkk1 = self.key
        print(kkk1, " - kkk1")
        kkk = codecs.decode(kkk1, 'hex_codec')
        print(kkk, "- KKK")
        encrypted = AESCipher(kkk).encrypt(xored, ivv)
        print(encrypted, " - ENCRYPTED")

        q = proof + encrypted
        response = requests.post(
            f"http://{self.host}:{self.port}/enroll",
            json={"type": "proof", "content": q, "key": self.key},
        ).json()

        if response["type"] == "ack":
            self.uid = proof[:2]
            self.is_enrolled = True

    def post(self, message=None):
        if not self.is_enrolled:
            print("Not enrolled")
            return ("Not enrolled")

        self.send_signature(message)
        while not self.is_message_posted():
            self.send_signature(message)
            time.sleep(self.config["fog"]["block_creation_interval"])

        self.send_linkverify()
        print("linkverify sended")
        while not self.is_message_posted():
            self.send_linkverify(message)
            time.sleep(self.config["fog"]["block_creation_interval"])

        self.prev_latest_nonce = self.latest_nonce

        if self.skip:
            self.send_proof()
            while not self.is_message_posted():
                self.send_proof()
                time.sleep(self.config["fog"]["block_creation_interval"])

    def is_message_posted(self):
        flag = 0
        while flag == 0:
            json_data = requests.get(f"http://{self.host}:{self.port}/get_root_of_trust").json()
            content_data = json_data['content']
            if content_data != 'No root of trust yet':
                flag = 1
                time.sleep(self.config["fog"]["block_creation_interval"])

        root_of_trust = RootOfTrust(
            block_id=content_data['block_id'],
            root_hash=content_data['root_hash'],
            total_number_of_users=content_data['total_number_of_users'],
            users_in_block=content_data['users_in_block'],
            flags=content_data['flags'],
            users=content_data['users'],
            redundancy=content_data['redundancy']
        )
        self.roots_of_trust.append(root_of_trust)

        if (self.roots_of_trust == []):
            return False
        latest_block = self.roots_of_trust[-1]
        if latest_block.block_id in self.checked_rots:
            return False

        self.checked_rots[latest_block.block_id] = True

        p = 0.6
        w = None
        if latest_block.flags[5] == "1":
            w = 8
        else:
            w = 4
        tunstall_tree = TunstallTree(p, w)
        print(self.uid, " - uid")
        return True

    def send_proof(self):

        proof = sha256(self.prev_latest_nonce.encode()).hexdigest()
        proof = self.uid + proof
        print("proof sended - ", proof)
        requests.post(
            f"http://{self.host}:{self.port}/contribute", json={"type": "proof", "content": proof}
        )

    def send_signature(self, message):
        print("in send_signature")
        self.latest_nonce = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )
        k = codecs.decode(self.prev_latest_nonce, 'hex_codec')
        # print(self.prev_latest_nonce, " - last nonce")
        # print(k, " - key")
        signature = AESCipher(k).encrypt(
            message, sha256(self.key.encode()).digest()[:16]
        )
        # print("sha key - ", sha256(self.key.encode()).digest()[:16])
        # print(signature, " - sign")
        signature = self.uid + signature
        print(signature, " - sign + uid")

        requests.post(
            f"http://{self.host}:{self.port}/contribute",
            json={"type": "signature", "content": signature},
        )
        print("contribute signature complete!")
        requests.post(
            f"http://{self.host}:{self.port}/store_data",
            json={"type": "store", "content": message},
        )
        print("store_data Signature complete!")

    def send_linkverify(self):
        print("in send_linkverify")
        linkverify = sxor(
            sha256(self.latest_nonce.encode()).hexdigest(), self.prev_latest_nonce
        )
        self.l = sxor(
            sha256(self.latest_nonce.encode()).hexdigest(), self.prev_latest_nonce
        )

        linkverify = (
                linkverify
                + sha256(
            (
                    sha256(self.latest_nonce.encode()).hexdigest()
                    + self.prev_latest_nonce
            ).encode()
        ).hexdigest()
        )
        linkverify = self.uid + linkverify
        requests.post(
            f"http://{self.host}:{self.port}/contribute",
            json={"type": "linkverify", "content": linkverify},
        )
        print("complete in send_linkverify")

    def receive(self, msg, type):
        if not self.is_enrolled:
            return
        match type:
            case "proof":
                if self.proof is None:
                    self.proof = msg
                    print(self.proof, " - proof is updated")
                else:
                    if (
                            sha256(sxor(self.prev_link, msg).encode()).hexdigest()
                            == self.proof
                    ):
                        print("Proof verified")
                        kkk = codecs.decode(sxor(self.prev_link, msg), 'hex_codec')
                        ivv = 16 * b'\x00'
                        unlock = sxor(
                            msg,
                            AESCipher(kkk).decrypt(
                                self.prev_signature, b"0123456789abcdef"
                            ),
                        )
                        print(f"Unlock H(B) = {unlock}")
                        root_of_trust = json.loads("{" + unlock + "}")
                        print(123123)
                        print("root of trust - ", root_of_trust)
                        self.roots_of_trust.append(RootOfTrust(root_of_trust["RootOfTrust"]["block_id"],
                                                               root_of_trust["RootOfTrust"]["root_hash"],
                                                               root_of_trust["RootOfTrust"]["total_number_of_users"],
                                                               root_of_trust["RootOfTrust"]["users_in_block"],
                                                               root_of_trust["RootOfTrust"]["flags"],
                                                               root_of_trust["RootOfTrust"]["users"],
                                                               root_of_trust["RootOfTrust"]["redundancy"]))
                        self.prev_proof = self.proof
                        self.proof = msg
                    else:
                        print("Could not verify proof")
                        print(" - self proof: ", self.proof)
                        print(" - self prev link: ", self.prev_link)
                        print(" - msg: ", msg)
            case "link":
                print("linkk")
                self.prev_link = self.link
                self.link = msg
            case "signature":
                print("sigg")
                self.prev_signature = self.signature
                self.signature = msg
            case _:
                pass

    def get_contribution(self, user_id, block_number):
        user_id_hex = user_id
        user_id = int(user_id, 16)
        block_number = int(block_number)
        block = None
        for root_of_trust in self.roots_of_trust:
            if root_of_trust.block_id == block_number:
                block = root_of_trust
                break
        p = 0.6
        w = None
        if block.flags[5] == "1":
            w = 8
        else:
            w = 4
        # w = 8
        tunstall_tree = TunstallTree(p, w)
        decoded_users_bitmap = tunstall_tree.decode_del(block.users)

        if decoded_users_bitmap[user_id] == '1':
            # Count number of 1s in bitmap that are before user_id
            count = 0
            for i in range(user_id):
                if decoded_users_bitmap[i] == '1':
                    count += 1
            response = requests.get(f"http://{self.host}:{self.port}/get_contribution",
                                    json={"user_id": count, "block_id": block_number}).json()
            return response
        else:
            print("User not in block")

    def check_contributions_in_block(self, user_id, block_number):
        response = requests.get(f"http://{self.host}:{self.port}/check_user_in_block",
                                json={"block": block_number, "user": user_id}).json()
        return response

    def step(self, payload, id_user):
        print(f"Received message: {payload} from user {id_user}")

    def listen2(self, user_id, first_p):
        host = self.config["fog"]["host"]
        port = self.config["fog"]["port"]

        contributions.append(Contribution(user_id, type="proof", content=first_p))

        temp = None

        prevLinkverify = None
        prevSignature = None
        currLinkverify = None
        currSignature = None
        currProof = None
        usedSignature = None
        usedLinkverify = None
        usedProof = None
        while True:
            response = requests.get(f"http://{host}:{port}/listen_user_contributions", json={"user": user_id}).json()
            time.sleep(1)
            if temp != response:
                a = response["content"]
                if (a == "user not found"):
                    continue
                if check_contribution(response["content"]):

                    if (a["type"] == "signature"):
                        prevSignature = currSignature
                        currSignature = Contribution(user_id, a["type"], a["content"][2:])
                    if (a["type"] == "linkverify"):
                        prevLinkverify = currLinkverify
                        currLinkverify = Contribution(user_id, a["type"], a["content"][2:])
                    if (a["type"] == "proof"):
                        currProof = Contribution(user_id, a["type"], a["content"][2:])

                    contributions.append(Contribution(user_id, a["type"], a["content"][2:]))
                    msg = None
                    if (
                            currLinkverify and currProof and currSignature and usedSignature != currSignature and usedLinkverify != currLinkverify and usedProof != currProof):
                        usedLinkverify = currLinkverify
                        usedSignature = currSignature
                        usedProof = currProof

                        msg = decrypt_message(currProof.content, currLinkverify.content, currSignature.content)

                        # Вызываем функцию приложения (hook) с параметрами msg и id_user
                        self.step(msg, user_id)
                    print("success!")

                else:
                    print("fail")
            temp = response

    def listen_for_two(self, first_user_id, first_p, second_user_id, second_p):
        host = self.config["fog"]["host"]
        port = self.config["fog"]["port"]

        contributions1.append(Contribution(first_user_id, type="proof", content=first_p))
        contributions2.append(Contribution(second_user_id, type="proof", content=second_p))

        temp1 = None
        temp2 = None

        prevLinkverify = None
        prevSignature = None
        currLinkverify1 = None
        currSignature1 = None
        currProof1 = None
        usedSignature1 = None
        usedLinkverify1 = None
        usedProof1 = None
        currLinkverify2 = None
        currSignature2 = None
        currProof2 = None
        usedSignature2 = None
        usedLinkverify2 = None
        usedProof2 = None
        flag = 0
        while True:
            response1 = requests.get(f"http://{host}:{port}/listen_user_contributions",
                                     json={"user": first_user_id}).json()
            time.sleep(1)
            if flag == 0:
                if temp1 != response1:
                    a = response1["content"]
                    if (a == "user not found"):
                        flag = 1
                        continue
                    if check_contribution1(response1["content"]):

                        if (a["type"] == "signature"):
                            prevSignature = currSignature1
                            currSignature1 = Contribution(first_user_id, a["type"], a["content"][2:])
                        if (a["type"] == "linkverify"):
                            prevLinkverify = currLinkverify1
                            currLinkverify1 = Contribution(first_user_id, a["type"], a["content"][2:])
                        if (a["type"] == "proof"):
                            currProof1 = Contribution(first_user_id, a["type"], a["content"][2:])

                        contributions1.append(Contribution(first_user_id, a["type"], a["content"][2:]))
                        msg = None
                        if (
                                currLinkverify1 and currProof1 and currSignature1 and usedSignature1 != currSignature1 and usedLinkverify1 != currLinkverify1 and usedProof1 != currProof1):
                            usedLinkverify1 = currLinkverify1
                            usedSignature1 = currSignature1
                            usedProof1 = currProof1

                            msg = decrypt_message(currProof1.content, currLinkverify1.content, currSignature1.content)

                            # Вызываем функцию приложения (hook) с параметрами msg и id_user
                            self.step(msg, first_user_id)
                        print("success user1!")

                    else:
                        print("fail")
                temp1 = response1
            if flag == 1:
                response2 = requests.get(f"http://{host}:{port}/listen_user_contributions",
                                         json={"user": second_user_id}).json()
                # user2
                print("ready for second user")
                if temp2 != response2 and flag == 1:
                    print(response2, " - listening for second user")

                    a = response2["content"]
                    if (a == "user not found"):
                        flag = 0
                        continue
                    if check_contribution2(response2["content"]):

                        if (a["type"] == "signature"):
                            prevSignature = currSignature2
                            currSignature2 = Contribution(second_user_id, a["type"], a["content"][2:])
                        if (a["type"] == "linkverify"):
                            prevLinkverify = currLinkverify2
                            currLinkverify2 = Contribution(second_user_id, a["type"], a["content"][2:])
                        if (a["type"] == "proof"):
                            currProof2 = Contribution(second_user_id, a["type"], a["content"][2:])

                        contributions2.append(Contribution(second_user_id, a["type"], a["content"][2:]))
                        msg = None
                        if (
                                currLinkverify2 and currProof2 and currSignature2 and usedSignature2 != currSignature2 and usedLinkverify2 != currLinkverify2 and usedProof2 != currProof2):
                            usedLinkverify2 = currLinkverify2
                            usedSignature2 = currSignature2
                            usedProof2 = currProof2

                            msg = decrypt_message(currProof2.content, currLinkverify2.content, currSignature2.content)

                            self.step(msg, second_user_id)
                        print("success user2!")

                    else:
                        print("fail")
                temp2 = response2


def decrypt_message(p1, lv, s):
    link = lv[:64]
    # print(sxor(p1,link), " - sxor")
    kkk = codecs.decode(sxor(p1, link), 'hex_codec')
    # print(kkk, " - kkk")
    decrypted_text = AESCipher(kkk).decrypt(s)
    h = sha256(decrypted_text.encode()).hexdigest()
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    host = config["fog"]["host"]
    port = config["fog"]["port"]
    response = requests.get(f"http://{host}:{port}/get_data", json={"content": h}).json()
    print(response)
    return response["content"]


def check_contribution1(message: Dict[str, Any]) -> bool:
    match message["type"]:

        case "proof":
            user_id = message["content"][:2]
            content = message["content"][2:]
            ContributionWithPos = namedtuple(
                "ContributionWithPos", ["contribution", "pos"]
            )
            proof_contrpos = None
            # Find latest contribution with the same UID and with proof type, and remember its position in this list
            for i, contribution in enumerate(contributions1):
                if contribution.user_id == user_id and contribution.type == "proof":
                    proof_contrpos = ContributionWithPos(contribution, i)

            failed = True
            N = None
            linkverify_contrpos = None
            # Start traversing list from position of the latest contribution with the same UID and with proof type
            for i, contribution in enumerate(contributions1[proof_contrpos.pos:]):  # here some important
                # Find linkverify contribution with the same UID
                if (
                        contribution.user_id == user_id
                        and contribution.type == "linkverify"
                ):
                    # Compute H(L xor content) != proof_contrpos.contribution.content
                    link = contribution.content[:64]
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
                        print("LV contrpos: " + str(linkverify_contrpos.pos))
                        break
            if failed:
                print("Jam Spoof detected")
                return False
            for contribution in contributions1[
                                proof_contrpos.pos: linkverify_contrpos.pos + 1
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
                    print("Jam spoof2")
            return False
        case "signature":
            return True
        case "linkverify":
            return True


def check_contribution2(message: Dict[str, Any]) -> bool:
    match message["type"]:

        case "proof":
            user_id = message["content"][:2]
            content = message["content"][2:]
            ContributionWithPos = namedtuple(
                "ContributionWithPos", ["contribution", "pos"]
            )
            proof_contrpos = None
            # Find latest contribution with the same UID and with proof type, and remember its position in this list
            for i, contribution in enumerate(contributions2):
                if contribution.user_id == user_id and contribution.type == "proof":
                    proof_contrpos = ContributionWithPos(contribution, i)

            failed = True
            N = None
            linkverify_contrpos = None
            # Start traversing list from position of the latest contribution with the same UID and with proof type
            for i, contribution in enumerate(contributions2[proof_contrpos.pos:]):  # here some important
                # Find linkverify contribution with the same UID
                if (
                        contribution.user_id == user_id
                        and contribution.type == "linkverify"
                ):
                    # Compute H(L xor content) != proof_contrpos.contribution.content
                    link = contribution.content[:64]
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
                        print("LV contrpos: " + str(linkverify_contrpos.pos))
                        break
            if failed:
                print("Jam Spoof detected")
                return False
            for contribution in contributions2[
                                proof_contrpos.pos: linkverify_contrpos.pos + 1
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
                    print("Jam spoof2")
            return False
        case "signature":
            return True
        case "linkverify":
            return True


def check_contribution(message: Dict[str, Any]) -> bool:
    match message["type"]:

        case "proof":
            user_id = message["content"][:2]
            content = message["content"][2:]
            ContributionWithPos = namedtuple(
                "ContributionWithPos", ["contribution", "pos"]
            )
            proof_contrpos = None
            # Find latest contribution with the same UID and with proof type, and remember its position in this list
            for i, contribution in enumerate(contributions):
                if contribution.user_id == user_id and contribution.type == "proof":
                    proof_contrpos = ContributionWithPos(contribution, i)

            failed = True
            N = None
            linkverify_contrpos = None
            # Start traversing list from position of the latest contribution with the same UID and with proof type
            for i, contribution in enumerate(contributions[proof_contrpos.pos:]):  # here some important
                # Find linkverify contribution with the same UID
                if (
                        contribution.user_id == user_id
                        and contribution.type == "linkverify"
                ):
                    # Compute H(L xor content) != proof_contrpos.contribution.content
                    link = contribution.content[:64]
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
                        print("LV contrpos: " + str(linkverify_contrpos.pos))
                        break
            if failed:
                print("Jam Spoof detected")
                return False
            for contribution in contributions[
                                proof_contrpos.pos: linkverify_contrpos.pos + 1
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
                    print("Jam spoof2")
            return False
        case "signature":
            return True
        case "linkverify":
            # print(message, " - lv msg")
            # message["content"] = b64decode(message["content"]).decode()
            # print(message["content"], " - b64 decode lv")
            return True


def get_pls():
    host = config["sequencer"]["host"]
    port = config["sequencer"]["port"]

    response = requests.get(f"http://{host}:{port}/getpls").json()

    thing.receive(response["content"]["link"], "link")
    thing.receive(response["content"]["signature"], "signature")
    thing.receive(response["content"]["proof"], "proof")


if __name__ == "__main__":
    print("Thing is working...")
    # read config yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    thing = Thing(config)
    schedule.every(10).minutes.do(get_pls)
    stop_run_continuously = run_continuously()
    while True:
        inp = input("Enter command: ")
        match inp:
            case "enroll":
                thing.enroll()
                print(f"Enrolled with UID {thing.uid}")
            case "post":
                msg = input("Enter message: ")
                thing.post(msg)
            case "pls":
                host = config["sequencer"]["host"]
                port = config["sequencer"]["port"]

                response = requests.get(f"http://{host}:{port}/getpls").json()

                thing.receive(response["content"]["link"], "link")
                thing.receive(response["content"]["signature"], "signature")
                thing.receive(response["content"]["proof"], "proof")
                print(response, " - response")

            case "get_contribution":
                user_id = input("Enter user id: ")
                block_number = input("Enter block number: ")
                print(thing.get_contribution(user_id, block_number))

            case "listen":
                user_id = input("Enter user id to listen: ")
                first_p = input("Enter p: ")
                thing.listen2(user_id, first_p)

            case "check":
                user_id = input("Enter user id: ")
                block_number = input("Enter block number: ")
                print(thing.check_contributions_in_block(user_id, block_number))
            case _:
                print("Invalid command")
