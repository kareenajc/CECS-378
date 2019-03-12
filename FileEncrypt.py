import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import json

def MyEncrypt(message, key):
    #checking key length
    if(len(key) < 32):
        raise ValueError("Key less than 32 Bytes!")
    
    #assigning values
    IV = os.urandom(16)
    backend = default_backend()
    
    #create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    
    #make encryptor
    encryptor = cipher.encryptor()
    
    #encrypt message
    C = encryptor.update(message) + encryptor.finalize()
    return C, IV

def MyFileEncrypt(filepath):
    #generating key
    key = os.urandom(32)
    
    #getting file name and extension
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    #reading file
    file = open(filepath, "rb")
    m = file.read()
    file.close()
    
    #initialize padder
    padder = padding.PKCS7(128).padder()
    
    #pad data to fit block size
    m = padder.update(m)
    m += padder.finalize()
    
    #calling encryption method
    C, IV = MyEncrypt(m, key)
    
    #storing values
    encData = {"C": str(C), "IV": str(IV), "key": str(key), "ext": ext}
    print(encData)

    #delete file
    #os.remove(filepath)
    
    #create and write to json
    filenameJSON = filename + ".json"
    newFile = open(filenameJSON, "w")
    
    #write json data to file
    with open(filenameJSON, "w") as outfile:
        json.dump(encData, outfile, ensure_ascii=False, indent=3)
        
    #with open(filenameJSON) as json_file:
    #    data = json.load(json_file)
        
    return C, IV, key, ext

def MyDecrypt(C, IV, key):
    #make cipher
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    
    #make decryptor
    decryptor = cipher.decryptor()
    
    #decrypt ciphertext
    plaintext = decryptor.update(C) + decryptor.finalize()

    #unpad message
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(message) + unpadder.finalize()
    
    return plaintext

def MyFileDecrypt(filepath, IV, key, ext):
    filename_ext = os.path.basename(filepath) #gets file name with extension from path
    filename, ext = os.path.splitext(filename_ext) #separates file name and extension
    
    jsonFile = filename + ".json"
    print(jsonFile)
    
    #open file to decrypt
    file = open(jsonFile, "rb")
    C = file.read()
    print(C)

    message = MyDecrypt(C, IV, key)

    writefile = open(filepath, "wb")
    writefile.write(message)

    return message, IV, key

def main():
    testFile = "test.txt"
    
    C, IV, key, ext = MyFileEncrypt(testFile)
    
    MyFileDecrypt(testFile, IV, key, ext)
    
main()