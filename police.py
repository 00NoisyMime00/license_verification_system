from code import Hash, RSA
import socket

class Police:
    def __init__(self):

        self.n_for_communication_with_verification_server = 1517
        # PHI is 1440, p is 37 and q is 41
        self.e_for_communication_with_verification_server = 659
        self.encryption_obj = RSA(self.n_for_communication_with_verification_server, self.e_for_communication_with_verification_server)
        
        # Create a socket object
        self.socket = socket.socket()		
        # Address of verification server.
        self.address = '127.0.0.1'
        # Port of verification server.
        self.port = 12345			

    @staticmethod
    def parse_data(data):
        parsed_data = ""
        for key in sorted(data.keys()):
            parsed_data += "".join(str(data[key]).split(" "))
        
        return parsed_data

    def verify_license(self, data, signature):
        # Parse data which is recieved in dict form.
        parsed_data = Police.parse_data(data)
        # Encrypt the data for communication.
        encrypted_parsed_data = self.encryption_obj.encrypt(parsed_data)
        
        # Get hash of parsed data.
        hash_of_data = Hash().generate_hash(parsed_data)['hash']

        # Connect to verifcation server.
        self.socket.connect((self.address, self.port))

        # Send parsed data.
        self.socket.send(encrypted_parsed_data.encode())
        self.socket.recv(10)
        # Send signature.
        encrypted_signature = self.encryption_obj.encrypt(signature)
        self.socket.send(encrypted_signature.encode())

        is_verfied = self.socket.recv(1024).decode()

        return is_verfied
            