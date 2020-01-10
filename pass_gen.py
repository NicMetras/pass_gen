from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Protocol.KDF import bcrypt
from Crypto.Protocol.KDF import bcrypt_check
from Crypto.Hash import SHA256
from base64 import b64encode
import os, time, sys, pkg_resources, random

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        return init_vector + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as pass_file:
            plaintext = pass_file.read()
        encrypted = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as pass_file:
            pass_file.write(encrypted)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        init_vector = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as pass_file:
            ciphertext = pass_file.read()
        decrypted = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as pass_file:
            pass_file.write(decrypted)
        os.remove(file_name)


def quick_gen():
    password = ""
    uppers = [cap for cap in alnums if cap.isupper()]
    lowers = [lower for lower in alnums if lower.islower()]
    
    while len(password) < 16:
        roll = random.choice(range(1,5))
        if roll == 1:
            upper_roll = random.choice(range(0,len(uppers)-1))
            password = password + uppers[upper_roll]
        elif roll == 2:
            lower_roll = random.choice(range(0,len(lowers)-1))
            password = password + lowers[lower_roll]
        elif roll == 3:
            num_roll = random.choice(range(0,9))
            password = password + str(num_roll)
        elif roll == 4:
            char_roll = random.choice(range(0,len(chars)-1))
            password = password + chars[char_roll]

    return password

def key_gen(password):
    salt = b'\xfc]CZ\x0f@r\xc9\x94\xa4\xc6ps\xec\x02\x85<IB\xca\xc7\xe0<sX\x07\xe9\xca\x86\xf4\x7f\t'
    return PBKDF2(password, salt, dkLen=32)

def hash_gen(password):
    b64_pword = b64encode(SHA256.new(str.encode(password)).digest())
    return bcrypt(b64_pword, 12)


chars = "@%+\/'!#$^?:.(){}[]~"

alnums = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


clear = lambda: os.system('clear')

print("pass_gen v1.1")
print("Select operating mode: [Q]uick [N]ew [R]ead [A]dd [H]elp")
mode = input("Selection: ")

if mode == "H" or mode == "h":
    print("Q: Quick mode, generate one-time strong password, does not add to profile")
    print("N: Create new profile. Select if first time running this program. WARNING: May overwrite existing profile if one for same user exists!")
    print("R: Read saved passwords from existing user profile.")
    print("A: Add password to existing user profile if one exists.")
    mode = input("Make selection: ")

if mode == "Q" or mode == "q":
    print("Generating strong password...")
    print(quick_gen())

elif mode == "N" or mode == "n":
    print("Enter a username and password for this user")
    while True:
        user = str(input("username: "))
        if os.path.exists(user + "_pass.txt.enc"):
            print("WARNING:file for this user exists, continuing will overwrite!\nctrl D at password prompt to quit.")
        password = str(input("Please choose a strong password! It will be used to encrypt your password file! \nEnter password: "))
        confirm_password = str(input("Confirm password: "))
        if password == confirm_password:
            break
        else:
            print("Passwords do not match!")
    
    clear()
    pass_file = user + "_pass.txt"

    p = open(pass_file, "w+")
    p.write(user + "'s passwords:\n\n")
    p.close()
    
    encryptor = Encryptor(key_gen(password))
    encryptor.encrypt_file(pass_file)
    
    b_hash = hash_gen(password)
    hash_file = user + "_data.txt"
    
    h = open(hash_file, "w+")
    h.write(b_hash.decode("utf-8"))
    h.close()
   
    print("Profile created! \nYou can now restart program and add to your encrypted passwords file.")
                
elif mode == "R" or mode == "r":
    print("Read mode:\nEnter username password to open your saved password file.")
   
    user = enc_file = dec_file = hash_file = ""
    while True:
        user = str(input("username:"))
        enc_file = user + "_pass.txt.enc"
        if not os.path.exists(enc_file):
            print("User does not exist!")
            e = str(input("Exit now to create new user or stay to reenter username.\nExit now? [y/n] "))
            if e == "Y" or e == "y":
                sys.exit()
        else:
            hash_file = user + "_data.txt"
            while True:
                password = str(input("password:"))
                bcrypt_hash = ''
                with open(hash_file, "r") as b:
                    bcrypt_hash = b.readlines()
                try:
                    b64_pword = b64encode(SHA256.new(str.encode(password)).digest())
                    bcrypt_check(b64_pword, str.encode(bcrypt_hash[0]))
                except ValueError:
                    print("incorrect password")
                else:
                    print("User verified...\nDecrypting " + enc_file + "...")
                    break
            break
    crypto = Encryptor(key_gen(password))
    crypto.decrypt_file(enc_file)
    
    dec_file = enc_file[:-4]
    
    with open(dec_file, "r") as f:
        for line in f:
            print(line)

    crypto.encrypt_file(dec_file)
     
elif mode == "A" or mode == "a":
    print("Add mode:\nAdd entries to your password file. First login then you will be prompted to supply your login info for a site you want to save.")
    user = enc_file = dec_file = hash_file = ""
    while True:
        user = str(input("username:"))
        enc_file = user + "_pass.txt.enc"
        if not os.path.exists(enc_file):
            print("User does not exist!")
            e = str(input("Exit now to create new user or stay to reenter username.\nExit now? [y/n] "))
            if e == "Y" or e == "y":
                sys.exit()
        else:
            hash_file = user + "_data.txt"
            while True:
                password = str(input("password:"))
                bcrypt_hash = ''
                with open(hash_file, "r") as b:
                    bcrypt_hash = b.readlines()
                try:
                    b64_pword = b64encode(SHA256.new(str.encode(password)).digest())
                    bcrypt_check(b64_pword, str.encode(bcrypt_hash[0]))
                except ValueError:
                    print("incorrect password")
                else:
                    print("User verified...\nDecrypting " + enc_file + "...")
                    break
            break
    crypto = Encryptor(key_gen(password))
    crypto.decrypt_file(enc_file)
    
    dec_file = enc_file[:-4]

    site = "site: "
    username = "username: "
    passwd = "password: "

    while True:
        with open(dec_file, "a+") as w:
            w.write(site + str(input(site)) + "\n")
            w.write(username + str(input(username)) + "\n")
            print("autogenerating strong password for this entry...")
            w.write(passwd + quick_gen() + "\n")
            w.write("\n")

        e = str(input("Add another? [y/n] "))
        if e == "N" or e == "n":
            break

    crypto.encrypt_file(dec_file)


                




