import time

import yaml

from client import Thing


class Construction(Thing):
    def step(self, payload, id_user):

        if id_user == factory1Uid:
            if payload == "confirm from factory1":
                print(payload, " - first response")
                setFirstFactory_true()
                print(getFirstFactory(), getSecondFactory(), " - first and second in first")
                if getFirstFactory() and getSecondFactory():
                    construction.post("go for deliver")
        if id_user == factory2Uid:
            if payload == "confirm from factory2":
                print(payload, " - first response")
                setSecondFactory_true()
                print(getFirstFactory(), getSecondFactory(), " - first and second in second")
                if getFirstFactory() and getSecondFactory():
                    construction.post("go for deliver")


first_factory = False
second_factory = False


def setFirstFactory_true():
    global first_factory
    first_factory = True


def setSecondFactory_true():
    global second_factory
    second_factory = True


def getFirstFactory():
    return first_factory


def getSecondFactory():
    return second_factory


if __name__ == "__main__":
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    construction = Construction(config)
    construction.enroll()
    print(construction.uid, " - uid")
    time.sleep(40)

    with open('keys.txt', 'r') as file:
        lines = file.readlines()

    factory1Firstp = lines[1].strip()
    factory2Firstp = lines[2].strip()
    factory1Uid = factory1Firstp[:2]
    factory2Uid = factory2Firstp[:2]
    print(factory1Firstp, " - f1p")
    print(factory2Firstp, " - f2p")

    construction.post("new order1")
    construction.post("new order2")


    def start_listen_for_two_factories():
        construction.listen_for_two(factory1Uid, factory1Firstp, factory2Uid, factory2Firstp)


    start_listen_for_two_factories()
    