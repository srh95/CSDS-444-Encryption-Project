def createKey(message, keyword):
    if(len(message) == len(keyword)):
        return keyword
    else:
        keylist = list(keyword)
        for i in range (len(message) - len(keylist)):
            keylist.append(keylist[i%len(keylist)])
    return "".join(keylist)

def encrypt(message, key):
    encryptedText = []
    for i in range (len(message)):
        currentChar = (ord(message[i]) +ord(key[i])) % 26
        currentChar += ord('A')  #add 'A's' order to make sure we are getting alphabetical order, should be 65
        encryptedText.append(chr(currentChar))
    return ("" . join(encryptedText))

def decrypt(encryptedMessage, key):
    decryptedText = []
    for i in range (len(encryptedMessage)):
        currentChar = (ord(encryptedMessage[i]) - ord(key[i]) + 26) % 26
        currentChar += ord('A')
        decryptedText.append(chr(currentChar))
    return "".join(decryptedText)

if __name__ == "__main__":
    message = "TEST TEST I AM MAKING A VIGENERE CIPHER"
    keyword = "GRACE"
    key = createKey(message, keyword)
    encryptedText = encrypt(message,key)
    print("Ciphertext :", encryptedText)
    print("Original/Decrypted Text :",
           decrypt(encryptedText, key))