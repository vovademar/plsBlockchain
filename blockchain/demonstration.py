import yaml

from client import Thing


class User2(Thing):
    # override step
    def step(self, payload, id_user):
        super().step(payload, id_user)
        try:
            print(int(payload) ** 2, " - sqr")
        except ValueError:
            print("Payload is not an integer, cannot compute square")


if __name__ == "__main__":
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    user2 = User2(config)
    firstp = "d3d4db723fe1fce89173fb792b6e817c658d99bdd401393177741048ac71b257"
    uid = firstp[:2]

    def start_listen2():
        user2.listen2(uid, firstp)

    start_listen2()
