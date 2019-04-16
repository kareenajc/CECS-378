import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
#from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json


CONST_RSA_KEY_SIZE = 2048
CONST_INDENT_SIZE = 4
CONST_PADDING_BITS = 128
constants = 32
KEY_LENGTH = 32
RSA_KEY_SIZE = 2048
IV_LENGTH = 16
PUBLIC_EXPONENT = 65537
RSA_PUBLIC_KEY_PATH = ".\RSApublickey.pem"
RSA_PRIVATE_KEY_PATH = ".\RSAprivatekey.pem"


def separateFileName(filepath):
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    return filename, ext

def writeJSON(dictionary, writeFile):
    #write json data to file
    with open(writeFile, "w") as outfile:
        json.dump(dictionary, outfile)
        outfile.close()

def MyEncrypt(message, key):
    #checking key length
    if(len(key) < KEY_LENGTH):
        raise ValueError("Key less than 32 Bytes!")
    
    #assigning values
    IV = os.urandom(IV_LENGTH)
    backend = default_backend()
    
    #initialize padder
    padder = padding.PKCS7(CONST_PADDING_BITS).padder()
    
    #pad data to fit block size
    message = padder.update(message) + padder.finalize()
    
    #create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    
    #make encryptor
    encryptor = cipher.encryptor()
    
    #encrypt message
    C = encryptor.update(message) + encryptor.finalize()
    return C, IV

def MyFileEncrypt(filepath):
    #generating key
    key = os.urandom(KEY_LENGTH)
    
    #getting file name and extension
    filename, ext = separateFileName(filepath)
    
    #reading file
    file = open(filepath, "rb")
    m = file.read()
    file.close()
    
    #calling encryption method
    C, IV = MyEncrypt(m, key)
    
    file = open(filepath, "wb")
    file.write(C)
    file.close()
    
    return C, IV, key, ext



def MyEncryptMAC(message, EncKey, HMACKey):
    
    #get ciphertext and IV
    C, IV = MyEncrypt(message, EncKey)
    
    #create HMAC object to make tag
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    tag = h.finalize()
    
    return C, IV, tag


def MyFileEncryptMAC(filepath):
    
    #create Keys
    KeyLength = 32
    HMACKey = os.urandom(KEY_LENGTH)
    EncKey = os.urandom(KEY_LENGTH)
    
    if len(EncKey) < KeyLength:
        raise Exception("EncKey less than 32 bytes!")
    if len(HMACKey) < KeyLength:
        raise Exception("HMACKey less than 32 bytes!")
    
    #open and read file to encrypt
    file = open(filepath, "rb")
    m = file.read()
    file.close()
    
    #getting file name and extension
    filename, ext = separateFileName(filepath)
    #encrypt & MAC
    C, IV, tag = MyEncryptMAC(m, EncKey, HMACKey)
    
    '''Not used for RSA'''
    #storing values
    encData = {"C": C.decode('cp437'), "EncKey": EncKey.decode('cp437'), "IV": IV.decode('cp437'),  "ext": ext, "tag": tag.decode('cp437')}
    
    filenameJSON = filename + ".json"
    
    writeJSON(encData, filenameJSON)
    
    #delete original file
    os.remove(filepath)

    return C, IV, tag, EncKey, HMACKey, ext

def CheckRSAKeys():
    publicExists = os.path.isfile(RSA_PUBLIC_KEY_PATH)
    privateExists = os.path.isfile(RSA_PRIVATE_KEY_PATH)
    
    if not publicExists or not privateExists:
        #generate and store private key
        privateKey = rsa.generate_private_key(
            public_exponent = PUBLIC_EXPONENT,
            key_size = RSA_KEY_SIZE,
            backend=default_backend()
            )
        
        privatepem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(RSA_PRIVATE_KEY_PATH, "wb") as privateKeyFile:
            privateKeyFile.write(privatepem)
    
        #generate and store public key
        publicKey = privateKey.public_key()
        
        publicpem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(RSA_PUBLIC_KEY_PATH, "wb") as publicKeyFile:
            publicKeyFile.write(publicpem)
        
# RSA Encrypt using AES CBC 256 Encryption with HMAC 
def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    (C, IV, tag, EncKey, HMACKey, ext) = MyFileEncryptMAC(filepath)
    
    key = EncKey + HMACKey
    
    #loads public key
    with open(RSA_Publickey_filepath, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend = default_backend()
        )
        
        #encrypts key to make RSACipher
        RSACipher = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
        )
        key_file.write(RSACipher)
        key_file.close()
        
        
        '''
        encData = {"C": C.decode('cp437'), "RSACipher": RSACipher.decode('cp437'),"EncKey": EncKey.decode('cp437'), "IV": IV.decode('cp437'),  "ext": ext, "tag": tag.decode('cp437')}
    
        filename, ext = separateFileName(filepath)
        
        filenameJSON = filename + ".json"
    
        writeJSON(encData, filenameJSON)
    
        #delete original file
        os.remove(filepath)
        '''

    return (RSACipher, C, IV, tag, ext) 

# AES requires plain text and ciphertext to be a multiple of 16
# We pad it so that the message is a multiple of the IV, 16
def addPadding(encoded):
	
	# We pad it with 128 bits or 16 bytes
	padder = padding.PKCS7(constants.CONST_PADDING_BITS).padder()

	# update() pads the encoded message
	padded_encoded = padder.update(encoded)

	# .finalize () Returns the remainder of the data.
	padded_encoded += padder.finalize()
	return padded_encoded  
   
def MyDecrypt(C, IV, key):
    #make cipher
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    
    #make decryptor
    decryptor = cipher.decryptor()
    
    #decrypt ciphertext
    plaintext_padded = decryptor.update(C) + decryptor.finalize()

    #unpad message
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
    
    return plaintext

def MyFileDecrypt(filepath, IV, key, ext):
    #getting file name and extension
    fileanme, ext = separateFileName(filepath)
    
    file = open(filepath, "rb")
    C = file.read()
    file.close()

    message = MyDecrypt(C, IV, key)
    
    writefile = open(filepath, "wb")
    writefile.write(message)
    writefile.close()

    return message, IV, key

def MyDecryptMAC(C, IV, tag, HMACKey, EncKey):
    
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    verifyTag = h.finalize()
    
    if verifyTag != tag:
        raise Exception("Tags do not align")
    
    message = MyDecrypt(C, IV, EncKey)
    
    return message

def MyFileDecryptMAC(originalfilepath, HMACKey):

    #getting file name and extension
    filename, ext = separateFileName(originalfilepath)
    
    jsonFile = filename + ".json"
    
    #open file to decrypt
    with open(jsonFile) as decryptFile:
        data = json.load(decryptFile)
        decryptFile.close()

    #getting data from dictionary
    C = (data['C']).encode('cp437')
    IV = (data['IV']).encode('cp437')
    tag = (data['tag']).encode('cp437')
    EncKey = (data['EncKey']).encode('cp437')
    message = MyDecryptMAC(C, IV, tag, HMACKey, EncKey)
    
     #write recovered data to file
    recoveredFile = open(originalfilepath, "wb")
    recoveredFile.write(message)
    recoveredFile.close()
    
    #remove json file
    os.remove(jsonFile)
    
    return message

def MyRSADecrypt(filepath, RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    #load private key file
    with open("RSA_Privatekey_filepath", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend()
        )
    
    
        plaintext = private_key.decrypt(
            RSACipher,
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
                )
        )
        key_file.close()
        
    EncKey = plaintext[0:31]
    HMACKey = plaintext[32:]
    
    message = MyFileDecryptMAC(filepath, HMACKey)
    return message


def main():
    #testFile = "test.txt"
    testFile = "test_photo.jpg"
    
    '''Regular'''
    #C, IV, key, ext = MyFileEncrypt(testFile)
    #input("File encrypted! Press enter to decrypt.")
    
    #MyFileDecrypt(testFile, IV, key, ext)
    #print("\nFile decrypted!")
    
    '''HMAC'''
    #C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(testFile)
    #input("File encrypted! Press enter to decrypt.")
    
    #MyFileDecryptMAC(testFile, HMACKey)
    #print("\nFile decrypted!")

    '''RSA'''
    #CheckRSAKeys()
    
    RSACipher, C, IV, tag, ext = MyRSAEncrypt(testFile, RSA_PUBLIC_KEY_PATH)
    input("File encrypted! Press enter to decrypt.")

    MyRSADecrypt(testFile, RSACipher, C, IV, tag, ext, RSA_PRIVATE_KEY_PATH)
    print("\nFile decrypted!")
    
main()