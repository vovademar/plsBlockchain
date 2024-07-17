class Bitmap:
    def __init__(self, max_user_id):
        # Calculate the size of the bytearray needed to hold the bitmap
        # for the given maximum user ID
        self.size = (max_user_id + 7) // 8
        self.bitmap = bytearray(self.size)

    def set(self, user_id):
        # Set the bit at the given user ID to 1
        byte_index = user_id // 8
        bit_index = user_id % 8
        self.bitmap[byte_index] |= 1 << bit_index

    def unset(self, user_id):
        # Set the bit at the given user ID to 0
        byte_index = user_id // 8
        bit_index = user_id % 8
        self.bitmap[byte_index] &= ~(1 << bit_index)

    def test(self, user_id):
        # Test the bit at the given user ID
        byte_index = user_id // 8
        bit_index = user_id % 8
        return (self.bitmap[byte_index] & (1 << bit_index)) != 0

    @staticmethod
    def compress_bitmap(bitmap):
        # Create a new bitmap with the same size as the original
        new_bitmap = Bitmap(len(bitmap.bitmap))
        new_user_id = 0
        for user_id in range(len(bitmap.bitmap) * 8):
            if bitmap.test(user_id):
                new_bitmap.set(new_user_id)
                new_user_id += 1
        return new_bitmap

    @staticmethod
    def compress_bitmap_fast(bitmap):
        set_bits = []
        for i in range(len(bitmap.bitmap) * 8):
            if bitmap.test(i):
                set_bits.append(i)
        new_bitmap = Bitmap(len(set_bits))
        mapping = {}
        for i, user_id in enumerate(set_bits):
            new_bitmap.set(i)
            mapping[i] = user_id
        return new_bitmap, mapping

    @staticmethod
    def decompress_bitmap(mapping, max_user_id):
        new_bitmap = Bitmap(max_user_id)
        for new_user_id, user_id in mapping.items():
            new_bitmap.set(user_id)
        return new_bitmap

    def print_bitmap(self):
        for i in range(len(self.bitmap) * 8):
            if self.test(i):
                print(1, end="")
            else:
                print(0, end="")
        print()
        
    def get_bitmap_str(self):
        bitmap_str = ""
        for i in range(len(self.bitmap) * 8):
            if self.test(i):
                bitmap_str += "1"
            else:
                bitmap_str += "0"
        return bitmap_str


if __name__ == "__main__":
    import random

    # Create a bitmap with 100 random user IDs set
    max_user_id = 100
    bitmap = Bitmap(max_user_id)
    for i in range(max_user_id):
        if random.random() > 0.8:
            bitmap.set(i)

    # Compress the bitmap
    compressed_bitmap, mapping = Bitmap.compress_bitmap_fast(bitmap)

    # Print the original bitmap
    print("Original bitmap:")
    bitmap.print_bitmap()
    # Print the compressed bitmap
    print("Compressed bitmap:")
    compressed_bitmap.print_bitmap()

    # Print the mapping of the bitmap
    print("Mapping of the bitmap:", mapping)

    # Decompress the bitmap
    decompressed_bitmap = Bitmap.decompress_bitmap(mapping, max_user_id)
    print("Decompressed bitmap:")
    decompressed_bitmap.print_bitmap()
    
    # Bitmap to int
    bitmap_str = bitmap.get_bitmap_str()
    bitmap_int = int("0000000010100", 2)
    print("Bitmap to int:", bitmap_int)
