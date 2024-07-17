from hashlib import sha256
from random import randint
import flask
import requests
import yaml

from cipher import AESCipher
from helpers.utils import sxor

import codecs


class Sequencer:
    def __init__(self, conig: dict):
        self.latest_nonce = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )
        self.prev_latest_nonce = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )
        self.latest_proof = None
        self.latest_link = None
        self.latest_signature = None

        self.host = config["fog"]["host"]
        self.port = config["fog"]["port"]

    def broadcast(self):
        root_of_trust = requests.get(f"http://{self.host}:{self.port}/get_root_of_trust").json()
        print(root_of_trust, " - root of trust")

        if root_of_trust["type"] != "success":
            return "empty", "empty", "empty"

        root_of_trust_json = "\"RootOfTrust\": {\"root_hash\": \"" + root_of_trust["content"][
            "root_hash"] + "\", \"total_number_of_users\": " + str(
            root_of_trust["content"]["total_number_of_users"]) + ", \"users_in_block\": " + str(
            root_of_trust["content"]["users_in_block"]) + ", \"flags\": \"" + root_of_trust["content"][
                                 "flags"] + "\", \"users\": \"" + root_of_trust["content"][
                                 "users"] + "\", \"redundancy\": \"" + root_of_trust["content"]["redundancy"] + "\"}"

        link = sxor(
            sha256(self.latest_nonce.encode()).hexdigest(), self.prev_latest_nonce
        )
        kkk1 = self.prev_latest_nonce
        kkk = codecs.decode(kkk1, 'hex_codec')
        signature = AESCipher(kkk).encrypt(
            sxor(root_of_trust_json, sha256(self.latest_nonce.encode()).hexdigest()),
            b"0123456789abcdef",
        )
        proof = sha256(self.prev_latest_nonce.encode()).hexdigest()

        self.latest_proof = proof
        self.latest_link = link
        self.prev_latest_nonce = self.latest_nonce
        self.latest_nonce = str(
            randint(
                1000000000000000000000000000000000000000000000000000000000000000,
                9999999999999999999999999999999999999999999999999999999999999999,
            )
        )

        return link, signature, proof

    def get_lp(self):
        return self.latest_link, self.latest_proof


app = flask.Flask(__name__)


@app.route("/getpls", methods=["GET"])
def get_pls():
    link, signature, proof = sequencer.broadcast()
    return flask.jsonify(
        {
            "type": "pls",
            "content": {"link": link, "signature": signature, "proof": proof},
        }
    )


@app.route("/get_lp", methods=["GET"])
def get_lp():
    link, proof = sequencer.get_lp()
    return flask.jsonify(
        {
            "type": "lp",
            "content": {"link": link, "proof": proof},
        }
    )


if __name__ == "__main__":
    # read config yaml
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    sequencer = Sequencer(config)

    app.run(port=config["sequencer"]["port"])
