import time

import yaml

from client import Thing


class Delivery(Thing):
    def step(self, payload, id_user):
        if id_user == constructionUid:
            print(payload, " - payload from construction")
            if payload == "go for deliver":
                delivery.post("delivered")
                print("delivered!!!!")


if __name__ == "__main__":
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        
    delivery = Delivery(config)
    delivery.enroll()
    print(delivery.uid, " - uid")
    time.sleep(5)

    with open('keys.txt', 'r') as file:
        lines = file.readlines()

    # factoryFirstp = lines[1].strip()
    # factoryUid = factoryFirstp[:2]
    
    constructionFirstp = lines[0].strip()
    constructionUid = constructionFirstp[:2]
    
    def start_listen2():
        delivery.listen2(constructionUid, constructionFirstp)

    start_listen2()
    