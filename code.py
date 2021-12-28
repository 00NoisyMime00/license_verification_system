
class Hash:
    '''
        mapping: a-0, b-1, c-2, d-3 ..., z-25.
    '''
    column_size = 25
    plaintext_space = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}

    # Helper function that gives the integer mapping of character.
    @staticmethod
    def int_from_char(c):
        if c.isdigit(): return int(c)
        if ord(c) >= 65 and ord(c) <= 90:
            return ord(c)-65
        raise Exception('Character is out of plaintext space.')
    
    # Helper function that gives the character of the corresponding iteger.
    @staticmethod
    def char_from_int(i):
        return chr(i+65)

    @staticmethod
    def generate_hash(plain_text):
        plain_text = plain_text.upper()
        plain_text = "".join(plain_text.split())

        # Appending 'Z' to make the total length a multiple of column size.
        plain_text += (((Hash.column_size - len(plain_text))%Hash.column_size) * 'Z')
        number_of_rows = len(plain_text) // Hash.column_size

        hash_value = list(plain_text[:Hash.column_size])
        for i in range(1, number_of_rows):
            for j in range(Hash.column_size):
                hash_value[j] = Hash.char_from_int((Hash.int_from_char(hash_value[j]) + Hash.int_from_char(plain_text[Hash.column_size*i + j]))%len(Hash.plaintext_space))
        
        return {'hash': "".join(hash_value), 'plaintext': plain_text}
    
class RSA:
    def __init__(self, n, e = None, d = None, block_size = 1):
        self.n = n
        self.e = e
        self.d = d
        self.block_size = block_size

    def encrypt(self, plaintext):
        n = self.n
        e = self.e
        block_size = self.block_size

        encrypted_block_list = []
        ciphertext = None

        if len(plaintext) > 0:
            ciphertext = ord(plaintext[0])
        
        for index, character in enumerate(plaintext):
            if index == 0: continue

            if index % block_size == 0:
                encrypted_block_list.append(ciphertext)
                ciphertext = 0
            
            ciphertext = ciphertext*1000 + ord(character)
        
        encrypted_block_list.append(ciphertext)

        for index, blocks in enumerate(encrypted_block_list):
            encrypted_block_list[index] = str((blocks ** e) % n)
        
        encrypted_message = " ".join(encrypted_block_list)
        return encrypted_message

    def decrypt(self, ciphertext):
        n = self.n
        d = self.d
        block_size = self.block_size
        
        encrypted_block_list = list(map(int, ciphertext.split(' ')))
        plaintext = ""

        decrypted_block_list = []
        for index, block in enumerate(encrypted_block_list):
            decrypted_block_list.append((block ** d) % n)

            block_to_string = ""
            for i in range(block_size):
                block_to_string = chr(decrypted_block_list[index] % 1000) + block_to_string
                decrypted_block_list[index] = decrypted_block_list[index] // 1000
            
            plaintext += block_to_string
        
        return plaintext

class TransportAuthority:
    def __init__(self):
        self.n = 2021
        # PHI is 1962, p is 43 and q is 42
        self.e = 547
        self.encryption_obj = RSA(self.n, self.e)

    @staticmethod
    def parse_data(data):
        parsed_data = ""
        for key in sorted(data.keys()):
            parsed_data += "".join(str(data[key]).split(" "))
        
        return parsed_data

    def generate_signed_license(self, data):
        parsed_data = TransportAuthority.parse_data(data)
        print('parsed data: {}'.format(parsed_data))
        hash_of_data = Hash().generate_hash(parsed_data)['hash']

        signature = self.encryption_obj.encrypt(hash_of_data)

        return {'hash': hash_of_data, 'signature': signature}

        
