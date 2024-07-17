def shuffle(n, k, size):
    # n is the number to be shifted
    # k is the amount of shift
    # get the actual number of bits for n
    mask = (1 << size) - 1 # a mask with all 1 bits up to size
    k = k % size # wrap around k if it exceeds size
    left = (n << k) & mask # shift n left by k bits and apply the mask
    right = n >> (size - k) # shift n right by size - k bits
    return left | right # combine the left and right parts with bitwise or

def shift(shuffled_value, v, n):
    shifted_value = (shuffled_value + v) % n
    return shifted_value

def shuffle_shifter(user_id, block_number, rounds):
    size = 8
    n = 2 ** size
    v = block_number
    F = 0x5EED
    for _ in range(rounds):
        shuffled = shuffle(user_id, 1, size)
        user_id = shift(shuffled, v, n)
        v = (F * v + 1) % n
    return user_id

def unshift(shifted_value, v, n):
    unshifted_value = (shifted_value - v + n) % n
    return unshifted_value

def unshuffle(n, k, size):
    mask = (1 << size) - 1
    k = k % size
    left = (n << (size - k)) & mask
    right = (n >> k) & mask
    return (left | right) & mask

def unshuffle_shifter(user_id, block_number, rounds):
    size = 8
    n = 2 ** size
    v = block_number
    F = 0x5EED
    for _ in range(rounds):
        v = (F * v + 1) % n
    for _ in range(rounds):
        v = (v - 1) * pow(F, -1, n) % n
        user_id = unshift(user_id, v, n)
        user_id = unshuffle(user_id, 1, size)
    return user_id



if __name__ == '__main__':
    user_id = 121
    block_number = 201
    rounds = 32
    shuffled = shuffle_shifter(user_id, block_number, rounds)
    unshuffled = unshuffle_shifter(shuffled, block_number, rounds)
    print(f"Original user id: {user_id}, shuffled user id: {shuffled}, unshuffled user id: {unshuffled}")
