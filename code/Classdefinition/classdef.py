from Crypto.Cipher import AES
import Crypto.Random as rand
from Crypto.Util import Counter
import Crypto.Protocol.KDF as KDF
import Crypto.Hash as Hash
from binascii import hexlify
import os
import base64

block_size = 32
IV_size = 16
SALT_BITS = 8

directory = os.path.join(os.getcwd(), "..")
data_directory = os.path.join(directory, "data")
code_directory = os.path.join(directory,"code")


pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def hashed(data_value, salt_value):
    hasher = Hash.SHA256.new()
    hasher.update(salt_value + ":" + data_value)
    data_value = base64.b64encode(hasher.digest())
    return data_value
    

class record:

    def __init__(self, service, username, password, mode, IV = None, salt = None):
        self.service = service
        self.username = username
        self.password = password
        self.mode = mode
        
        self.IV = IV
        
        if salt == None:
            self.salt = base64.b64encode(str(rand.new().read(SALT_BITS)))
        else:
            self.salt = salt
        

    def encrypt(self, master_password, v = None):
        key = KDF.PBKDF2(master_password, self.salt, 32, 2000)
        if self.mode == "CBC":
            m = AES.MODE_CBC
            self.IV = str(rand.new().read(IV_size))
            aes_encryptor = AES.new(key, m, self.IV)
        elif self.mode == "ECB":
            m = AES.MODE_ECB
            self.IV = str(rand.new().read(IV_size))
            aes_encryptor = AES.new(key, m, self.IV)
        elif self.mode == "CTR":
            m = AES.MODE_CTR
            self.IV = int(hexlify(rand.new().read(IV_size)),16)
            ctr = Counter.new(128, initial_value=self.IV)
            aes_encryptor = AES.new(key, m, counter=ctr)
            self.IV = str(self.IV)

        if v == None:
            self.username = pad(self.username)
            self.username = base64.b64encode(aes_encryptor.encrypt(self.username))
        
        if v != None:
            self.password = hashed(self.password, self.salt)
        
        self.password = pad(self.password)
        

        self.password = base64.b64encode(aes_encryptor.encrypt(self.password))

        self.IV = base64.b64encode(self.IV)
        
        self.mode = base64.b64encode(self.mode)
        self.service = base64.b64encode(self.service)
        self.salt = base64.b64encode(self.salt)
        
        key = None
        aes_encryptor = None
        master_password = None
        
    def decrypt(self, master_password, v = None):

        self.salt = base64.b64decode(self.salt)
        key = KDF.PBKDF2(master_password, self.salt, 32, 2000)
        
        self.IV = base64.b64decode(self.IV)
        
        self.mode = base64.b64decode(self.mode)
        self.service = base64.b64decode(self.service)
        
        if v == None:
            self.username = base64.b64decode(self.username)
        
        self.password = base64.b64decode(self.password)
        
        if self.mode == "CBC":
            m = AES.MODE_CBC
            aes_decryptor = AES.new(key, m, self.IV)
        elif self.mode == "ECB":
            m = AES.MODE_ECB
            aes_decryptor = AES.new(key, m, self.IV)
        elif self.mode == "CTR":
            m = AES.MODE_CTR
            self.IV = long(self.IV)
            ctr = Counter.new(128, initial_value = self.IV)
            aes_decryptor = AES.new(key, m, counter = ctr)
            
        if v == None:
            self.username = aes_decryptor.decrypt(self.username)
            self.username = unpad(self.username)
        
        self.password = aes_decryptor.decrypt(self.password)

        
        self.password = unpad(self.password)
        
        key = None
        aes_decryptor = None
        master_password = None


    def write(self, filename, target_directory):
        os.chdir(target_directory)
        myfile = open(filename,"a")
        write_string = self.service + " " + self.username + " " + self.password + " " + self.mode + " " + str(self.IV) + " " + self.salt + "\n"
        myfile.write(write_string)
        myfile.flush()
        myfile.close()
        os.chdir(code_directory)
        return True