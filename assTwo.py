import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding        #packages
from cryptography.hazmat.backends import default_backend   
from cryptography.hazmat.primitives import hashes, hmac



#Generate a 16 Bytes IV, and encrypt the message using the key and IV in CBC mode (AES).
#Return an error if the len(key) < 32, The key, 32 bytes= 256 bits.
#This function takes in a message,the user wants to encrypt along with a randomly
#generated key. Returns an encrypted message and a randomly generated IV

def MyEncrypt(message, key):
    
    #checking key length, must be 32 bytes
    if(len(key) < 32):
        return "Key is too short!"
    try:
        message = message.encode()
    except:
        pass
   
    IVLength = 16      #intialize 16 byte pseudo random IV  generate in os 
    IV = os.urandom(IVLength)  
    backend = default_backend()
    
    #initialize padder with OKCS7
    padder = padding.PKCS7(128).padder()
    pad_data = padder.update(message) + padder.finalize()  # pad the message and save
    message = pad_data
   #(encrypt msg in CBC mode)
   
    #setting up AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    
    #generate an encryptor object
    encryptor = cipher.encryptor()
    
    #generating cipher text
    C = encryptor.update(message) + encryptor.finalize()
    return C, IV      # c is encrypted msg with random IV





#This method takes in a filepath of an image that want to encrypt
def MyFileEncrypt(filepath):
    #generating a random 32 (pseudorandom)bit key
    keylength = 32
    key = os.urandom(keylength)
    
    
    #open the filepath as rb as single byte string and read as msg(becomes message) then close
    
    file = open(filepath, "rb")      # filepath is ARGUEMENT WHERE FILE LOCATED
    m = file.read()
    file.close()
    
     #calling encryption method,  encrypt message using Myencrypt
    C, IV = MyEncrypt(m, key) #  THESE C, IV are diffrent 
    #open file path as wb , write cipher to file then close it
    file = open(filepath, "wb")
    file.write(C)
    file.close()
    
    #gets file name with extension from path
    filename_ext = os.path.basename(filepath) 
    #separates file name and get extension of filepath
    filename, ext = os.path.splitext(filename_ext) 
    
    return C, IV, key, ext


    #return message, IV, key
    
def MyEncryptMAC(message, EncKey, HMACKey):
        
    C, IV = MyEncrypt(message, EncKey)
    
    #create HMAC object to c to get a tag
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) # improve the myEncryot method
    
    h.update(C)
    
    tag = h.finalize()  #to clean up execution
    
    return C, IV, tag   #return new msg C and





def MyFileEncryptMAC(filepath): # call to encrypt file with HMAC
    
    #create pseudorandom EncKey and HMACKey
    KeyLength = 32
    
    HMACKey = os.urandom(KeyLength)
    
    EncKey = os.urandom(KeyLength)
    
    if len(EncKey) < KeyLength:
        print("EncKey is too small!")
    if len(HMACKey) < KeyLength:
        print("HMACKey  is too small!")
    
    #open and readpath as rb, read it as msg 
    file = open(filepath, "rb")
    m = file.read()
    file.close()
    
     #encrypt & MAC, get extension of filepath
    C, IV, tag = MyEncryptMAC(m, EncKey, HMACKey)
    
    #getting file name and extension
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    file = open(filepath, "wb")
    file.write(C)
    file.close()

    return C, IV, tag, EncKey, HMACKey, ext

def MyDecrypt(C, IV, key):
    #make cipher, Seting cipher to AES, CSC with backend default
    backend = default_backend()
    #decrypt cipher text in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend = backend)
    
    #generate  decryptor as object
    decryptor = cipher.decryptor()
    
    #decrypt ciphertext, get this cipher txt and decrypt it to plainText
    message = decryptor.update(C) + decryptor.finalize() #
    
    #unpading result message
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(message) + unpadder.finalize() # decrypting the msg
    
    #return decoded message only if necessary
    #return message
    try:
        return message.decode("utf-8")
    except:
        return message

# Encrypt msg using MyEncryp
def MyFileDecrypt(filepath, IV, key, ext):  # opening file to get msg
    #getting file name and extension
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    file = open(filepath, "rb")
    C = file.read()
    file.close()
    # Decrypt cipher use MyDecrypt
    message = MyDecrypt(C, IV, key) # calling above method to decrypt message
    
    writefile = open(filepath, "wb")
    writefile.write(message)
    writefile.close()


def MyDecryptMAC(C, IV, tag, EncKey, HMACKey):
    # aply HMAC to cipher for getting second tag for verification
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    
    h.update(C)
    
    Tag2 = h.finalize()
    
    if Tag2 != tag:
        print("Invalid Tag")     # if tags are not same
    
    message = MyDecrypt(C, IV, EncKey)  # using MyDecrypt to decrypt cipherText
    
    return message

def MyFileDecryptMAC(filepath, C, IV , tag, EncKey, HMACKey, ext):
    # open filepath as rb, read as ciphertext (C), close
    #file = open(filepath, "rb")
    #C = file.read()
    #file.close()
    # use MydecryptMAC to decrypt ciphertext (C)
    message = MyDecryptMAC(C, IV, tag, EncKey, HMACKey)
    # open filepath as wb, write message to file, close
    file = open(filepath, "wb")
    file.write(message)
    file.close()
    
    
def main():
   testFile = "pic2.png"
    
   C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(testFile)
   input("File encrypted! Press enter to decrypt.")
    
   MyFileDecryptMAC(testFile, C , IV, tag, EncKey, HMACKey, ext)
   print("\nFile decrypted!")
main()
