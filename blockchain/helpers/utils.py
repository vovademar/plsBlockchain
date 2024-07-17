def sxor(s1: str, s2: str) -> str:
    """
    Compute the XOR of two strings of different lengths
    """
    if len(s1) < len(s2):
        s1 = s1 + "0" * (len(s2) - len(s1))
    elif len(s2) < len(s1):
        s2 = s2 + "0" * (len(s1) - len(s2))
    
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

if __name__ == "__main__":
    nonce = "5182719778894029509079603301776383692319725135930366493256529279"
    proof = "c742c38bcad3ee25418e255e75648ea09c4cc10402f789dc7dbff20dc6b5c15b"
    print(sxor(nonce, proof))