import Crypto.Hash as Hash
import Crypto.Protocol.KDF as KDF
import Crypto.Random as rand
from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import hexlify
import base64
import os
password = "myname1"

hasher = Hash.SHA256.new()
hasher.update(password)

print "%s" % hasher