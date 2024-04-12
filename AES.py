import sys
from BitVector import *

class AES ():
    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__ (self , keyfile :str ) -> None :
        self.key = open(keyfile, "r").readlines()[0]
        self.keysize = len(self.key) * 8
        self.AES_modulus = BitVector(bitstring='100011011')
    
    # encrypt - method performs AES encryption on the plaintext
    # and writes the ciphertext to
    # disk
    # Inputs : plaintext (str) - filename containing plaintext
    # ciphertext (str) - filename containing ciphertext
    # Return : void
    def encrypt (self , plaintext :str , ciphertext :str ) -> None :
        message_bv = BitVector(filename = plaintext)
        key_bv = BitVector(textstring = self.key)
        
        # Generating Key Schedule
        key_words = self.gen_key_schedule(key_bv)
        key_schedule = []
        for word in key_words:
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
        
        subBytesTable = self.gen_subbytes_table()
        
        final = BitVector(size = 0)
        while (message_bv.more_to_read):
            bitvec = message_bv.read_bits_from_file( 128 )
            if len(bitvec) < 128:
                bitvec.pad_from_right(128 - len(bitvec))
            if bitvec._getsize() > 0:
                # Add Round Key
                bitvec ^= BitVector(hexstring = round_keys[0])
                
                for round_count in range(num_rounds):
                    # Substitute Bytes Step
                    for i in range(16):
                        sub_bitvec = bitvec[i*8:i*8 + 8]
                        [LE, RE] = sub_bitvec.divide_into_two()
                        LE = int(LE)
                        RE = int(RE)
                        sub_byte = subBytesTable[LE*16 + RE]
                        sub_byte = BitVector(intVal = sub_byte, size = 8)
                        bitvec = bitvec[0:i*8] + sub_byte + bitvec[i*8 + 8:]
                    
                    # Shift Rows Step
                    bitvec = [[bitvec[j*32 + i*8:j*32 + i*8 + 8] for i in range(4)] for j in range(4)]
                    bitvec = [[row[i] for row in bitvec] for i in range(len(bitvec[0]))]
                    
                    bitvec[0] = [bitvec[0][0], bitvec[0][1], bitvec[0][2], bitvec[0][3]]
                    bitvec[1] = [bitvec[1][1], bitvec[1][2], bitvec[1][3], bitvec[1][0]]
                    bitvec[2] = [bitvec[2][2], bitvec[2][3], bitvec[2][0], bitvec[2][1]]
                    bitvec[3] = [bitvec[3][3], bitvec[3][0], bitvec[3][1], bitvec[3][2]]

                    transform_bitVec = BitVector(size = 0)
                    for i in range(4):
                        for j in range(4):
                            transform_bitVec += bitvec[j][i]
                    
                    # Mix Columns Step
                    if round_count != num_rounds - 1:
                        bitvec2 = [[None for _ in range(4)] for _ in range(4)]
                        for i in range(4):
                            for j in range(4):
                                a = bitvec[j][i]
                                b = bitvec[(j + 1) % 4][i]
                                c = bitvec[(j + 2) % 4][i]
                                d = bitvec[(j + 3) % 4][i]
                                two = BitVector(bitstring = '00000010')
                                three = BitVector(bitstring = '00000011')
                                bitvec2[j][i] = (a.gf_multiply_modular(two, self.AES_modulus, 8) ^ b.gf_multiply_modular(three, self.AES_modulus, 8)) ^ (c ^ d) 
                        
                        transform_bitVec = BitVector(size = 0)
                        for i in range(4):
                            for j in range(4):
                                transform_bitVec += bitvec2[j][i]

                    # Adding Round Key
                    transform_bitVec ^= BitVector(hexstring = round_keys[round_count + 1])
                    bitvec = transform_bitVec
                final += bitvec

        final_hex = final.get_bitvector_in_hex()
        f = open(ciphertext, "w")
        f.write(final_hex)   
        

    def gen_key_schedule (self, key_bv):
        len_key_words = 60
        len_i = 8
        byte_sub_table = self.gen_subbytes_table()
        key_words = [None for i in range(len_key_words)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(len_i):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(len_i, len_key_words):
            if i % len_i == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-len_i] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words


    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    
    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable

    
    def gen_invsubbytes_table(self):
        d = BitVector(bitstring='00000101')
        invSubBytesTable = []
        for i in range(0, 256):
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
        return invSubBytesTable

    # decrypt - method performs AES decryption on the
    # ciphertext and writes the
    # recovered plaintext to disk
    # Inputs : ciphertext (str) - filename containing ciphertext
    # decrypted (str) - filename containing recovered
    # plaintext
    # Return : void
    def decrypt (self , ciphertext :str , decrypted :str ) -> None :
        # encrypt_bv = BitVector(filename = ciphertext)
        key_bv = BitVector(textstring = self.key)

        hex_str = open(ciphertext, "r").readlines()[0]
        bv = BitVector(hexstring = hex_str)

        FILEOUT = open('temp.bin', 'wb')
        bv.write_to_file(FILEOUT)
        FILEOUT.close()
        encrypt_bv = BitVector(filename='temp.bin')

        # Generating Key Schedule
        key_words = self.gen_key_schedule(key_bv)
        key_schedule = []
        for word in key_words:
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
        round_keys.reverse()

        invSubBytesTable = self.gen_invsubbytes_table()
        
        final = BitVector(size = 0)
        encrypt_bv = BitVector(filename = 'temp.bin')
        while (encrypt_bv.more_to_read):
            bitvec = encrypt_bv.read_bits_from_file( 128 )
            if len(bitvec) < 128:
                bitvec.pad_from_right(128 - len(bitvec))
            if bitvec._getsize() > 0:
                # Add Round Key
                bitvec ^= BitVector(hexstring = round_keys[0])

                for round_count in range(num_rounds):
                    # Inv Shift Rows Step
                    bitvec = [[bitvec[j*32 + i*8:j*32 + i*8 + 8] for i in range(4)] for j in range(4)]
                    bitvec = [[row[i] for row in bitvec] for i in range(len(bitvec[0]))]
                    
                    bitvec[0] = [bitvec[0][0], bitvec[0][1], bitvec[0][2], bitvec[0][3]]
                    bitvec[1] = [bitvec[1][3], bitvec[1][0], bitvec[1][1], bitvec[1][2]]
                    bitvec[2] = [bitvec[2][2], bitvec[2][3], bitvec[2][0], bitvec[2][1]]
                    bitvec[3] = [bitvec[3][1], bitvec[3][2], bitvec[3][3], bitvec[3][0]]

                    transform_bitVec = BitVector(size = 0)
                    for i in range(4):
                        for j in range(4):
                            transform_bitVec += bitvec[j][i]
                    
                    # Inv Substitute Bytes Step
                    for i in range(16):
                        sub_bitvec = transform_bitVec[i*8:(i*8 + 8)]
                        [LE, RE] = sub_bitvec.divide_into_two()
                        LE = int(LE)
                        RE = int(RE)
                        sub_byte = invSubBytesTable[LE*16 + RE]
                        sub_byte = BitVector(intVal = sub_byte, size = 8)
                        transform_bitVec = transform_bitVec[0:i*8] + sub_byte + transform_bitVec[(i*8 + 8):]

                    # Add Round Key
                    transform_bitVec ^= BitVector(hexstring = round_keys[round_count + 1])

                    bitvec = [[transform_bitVec[j*32 + i*8:j*32 + i*8 + 8] for i in range(4)] for j in range(4)]
                    bitvec = [[row[i] for row in bitvec] for i in range(len(bitvec[0]))]
                    transform_bitVec = BitVector(size = 0)
                    for i in range(4):
                        for j in range(4):
                            transform_bitVec += bitvec[j][i]

                    # Inv Mix Columns Step
                    if round_count != num_rounds - 1:
                        bitvec2 = [[None for _ in range(4)] for _ in range(4)]
                        for i in range(4):
                            for j in range(4):
                                a = bitvec[j][i]
                                b = bitvec[(j + 1) % 4][i]
                                c = bitvec[(j + 2) % 4][i]
                                d = bitvec[(j + 3) % 4][i]
                                E_hex = BitVector(hexstring = '0E')
                                B_hex = BitVector(hexstring = '0B')
                                D_hex = BitVector(hexstring = '0D')
                                nine_hex = BitVector(hexstring = '09')
                                bitvec2[j][i] = (a.gf_multiply_modular(E_hex, self.AES_modulus, 8) ^ b.gf_multiply_modular(B_hex, self.AES_modulus, 8)) ^ \
                                    (c.gf_multiply_modular(D_hex, self.AES_modulus, 8) ^ d.gf_multiply_modular(nine_hex, self.AES_modulus, 8)) 

                        transform_bitVec = BitVector(size = 0)
                        for i in range(4):
                            for j in range(4):
                                transform_bitVec += bitvec2[j][i]

                    bitvec = transform_bitVec
                final += bitvec

        final_str = final.get_bitvector_in_ascii()
        f = open(decrypted, "w", encoding="utf-8")
        f.write(final_str)    


if __name__ == '__main__':
    cipher = AES ( keyfile = sys. argv [3])
    if sys. argv [1] == "-e":
        cipher . encrypt ( plaintext = sys. argv [2], ciphertext = sys.argv [4])
    elif sys. argv [1] == "-d":
        cipher . decrypt ( ciphertext = sys. argv [2], decrypted = sys.argv [4])
    else :
        sys . exit (" Incorrect Command - Line Syntax ")