# import the socket library
import socket	
from code import Hash, RSA		

# create a socket object
s = socket.socket()		
print ("Socket successfully created")

# reserve a port 
port = 12345

# Public key to decrypt signature.
n_for_license_data = 2021
d_for_license_data = 883

# Public key to decrypt data.
n_for_encrypted_data = 1517
d_for_encrypted_data = 59

# bind to the port
s.bind(('', port))		
print ("socket binded to {}".format(port))

# set socket into listening mode
s.listen(5)	
print ("socket is listening")		

# a forever loop until interrupted or
# an error occurs
while True:

    # Establish connection with police.
    c, addr = s.accept()	
    print ('Got connection from', addr )

    # Recieve encrypted parsed data from police.
    encrypted_data = c.recv(10240).decode()
    # Decrypte parsed data.
    data = RSA(n_for_encrypted_data, None, d_for_encrypted_data).decrypt(encrypted_data)

    c.send('1'.encode())
    # Recieve signature from police.
    encrypted_signature = c.recv(10249).decode()
    signature = RSA(n_for_encrypted_data, None, d_for_encrypted_data).decrypt(encrypted_signature)

    # Generate hash of data.
    hash_of_data = Hash().generate_hash(data)['hash']
    
    # Decrypt the signature.
    decrypted_hash = RSA(n_for_license_data, None, d_for_license_data).decrypt(signature)

    # send the result to the police officer. encoding to send byte type.
    c.send(str(decrypted_hash == hash_of_data).encode())

    # Close the connection with the police.
    c.close()
