import time

import yaml

from client import Thing


class Factory2(Thing):
    def step(self, payload, id_user):
        print(payload, " - payload")
        if id_user == constructionUid:
            if payload == "new order2":
                time.sleep(55)
                factory.post("confirm from factory2")
                # time.sleep(3)
                # factory.post("ready for delivery")


if __name__ == "__main__":
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        
    factory = Factory2(config)
    factory.enroll()
    print(factory.uid, " - uid")
    time.sleep(5)

    with open('keys.txt', 'r') as file:
        lines = file.readlines()

    constructionFirstp = lines[0].strip()
    constructionUid = constructionFirstp[:2]
    
    def start_listen2():
        factory.listen2(constructionUid, constructionFirstp)

    start_listen2()
    