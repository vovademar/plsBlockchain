import time

import yaml

from client import Thing

import client
import threading

if __name__ == "__main__":

    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
    thing = Thing(config)
    
    thing.enroll()
    print(thing.uid, " - userID")
    
    time.sleep(20)
    thing.post("1")
    thing.post("2")
    thing.post("3")
    thing.post("4")
