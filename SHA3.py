import numpy as np 

class SHA3:
    keccakf_rounds = 24

    kecckaf_consts = np.array([0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008], dtype=np.uint64)

    keccakf_rot = [1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    ]

    keccakf_pil = [
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    ]

    def __init__(self, hash_len):
        self.hash_len = hash_len
    
    def update_bytes(self):
        byte_n = 0
        for w in self.words:
            mask = np.uint64(0xFF)
            for i in range(8):
                self.bytes[byte_n] = np.uint8(int(mask & w) >> (8 * i))
                byte_n += 1
                mask = rotate_left(mask, 8)

    def update_words(self):
        j = 0
        for i in range(0, len(self.bytes)-8, 8):
            bytelist = self.bytes[i:i+8]
            word = np.uint64(0)
            for b in range(len(bytelist)):
                word ^= (np.uint64(bytelist[b] << 8*b))
            self.words[j] = word
            j += 1

    def reset_states(self, hash_len):
        self.bytes = np.zeros(200, dtype=np.uint8)
        self.words = np.zeros(25, dtype=np.uint64)

        self.pt = 0
        self.rsize = 200 - 2 * hash_len
        self.hash_len = hash_len

    def keccakf(self, state):
        out = [0 for _ in range(5)]
        for r in range(self.keccakf_rounds):

            # Computing Theta
            out = [state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20] for i in range(5)]

            for i in range(5):
                for j in range(0, 25, 5):
                    state[j+i] ^= (out[(i+4) % 5] ^ rotate_left(out[(i+1) % 5], 1))

            # Computing Rho Pi
            curr = state[1]

            for i in range(24):
                out[0] = state[self.keccakf_pil[i]]
                state[self.keccakf_pil[i]] = rotate_left(curr, self.keccakf_rot[i])
                curr = out[0]

            # Computing Chi
            for i in range(0, 25, 5):
                out = [state[j + i] for j in range(5)]

                for j in range(5):
                    state[j + i] ^= np.uint64(int(~out[(j + 1) % 5]) & int(out[(j + 2) % 5]))

            # Computing Iota
            state[0] ^= self.kecckaf_consts[r]

        self.update_bytes()
    
    def update(self, data):
        j = self.pt

        for i in range(len(data)):
            self.bytes[j] ^= data[i]
            j += 1
            if (j >= self.rsize):
                self.update_words()
                self.keccakf(self.words)
                j = 0

        self.pt = j

    def final(self):
        self.bytes[self.pt] ^= 0x06
        self.bytes[self.rsize - 1] ^= 0x80
        self.update_words()
        self.keccakf(self.words)

        out =  np.array([self.bytes[i] for i in range(self.hash_len)])

        return out

    def calculate(self, msg):
        self.reset_states(self.hash_len)
        self.update(msg)
        out = self.final()

        return out

    def calculate_from_file(self, filename):
        file_str = None

        with open(filename, 'rb') as f:
            file_str = f.read()
        
        bytearr = np.array([c for c in file_str])
        sha = self.calculate(bytearr)

        return sha, bytearray_to_hex(sha)
        
def str_to_bytearray(string):
   return np.array([ord(c) for c in string], dtype=np.uint8)

def bytearray_to_hex(bytearray):
    bin_array = ["{0:0{1}x}".format(b, 2) for b in bytearray]
    return ''.join(bin_array)

def hex_to_bytearray(hex):
    byte =[int(hex[i:i+2], 16) for i in range(0, len(hex)-1, 2)]

    if (len(hex) % 2):
        byte.append(int(hex[-1], 16))
    return np.array(byte, dtype=np.uint8)


def rotate_left(x, y, max_bits = 64):
    return np.uint64((int(x) << y) & (2**max_bits - 1) | (int(x) >> (max_bits - y)))

def rotate_right(x, y, max_bits=64):
    return ((int(x) >> y) | (int(x) << (max_bits - y) & (2* max_bits -1)))
  

if __name__ == '__main__':
    sha256 = SHA3(32)
    hex_test = '9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10'
    hex_sha_test = '2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF' 

    b = hex_to_bytearray(hex_test)
    sha_gen = sha256.calculate(b)

    print("Generated SHA3-256: ", sha_gen)
    print("Expected SHA3-256: ", hex_to_bytearray(hex_sha_test))

    if np.all(sha_gen == hex_to_bytearray(hex_sha_test)):
        print('Match!')
    else:
        print("SHAs dont match.")