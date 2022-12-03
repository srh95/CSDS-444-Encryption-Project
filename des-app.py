from flask import Flask, render_template, request, redirect, url_for, flash
import DES, md5, vigenereCipher
from RSA import *
import time


app = Flask(__name__)

# DES global variables
cipher_text = ""
cipher_text_blocks = []
rk = []
rkb = []
des_key = DES.bin2hex(DES.rand_key(64))

# MD5 global variables
digital_signature = ""
plain_text = ""

# RSA global variables
public, private = generate_keypair(generate_prime(), generate_prime())
encryptionRedirected = False
decryptionRedirected = False

# Vigenere Cipher global variables
messages = []

# Home page
@app.route('/')
def home():
    return render_template('home.html')

# Runs when clicking the generate new primes button
@app.get("/des/generate")
def des_generate():
    global des_key
    # generate secret key
    des_key = DES.bin2hex(DES.rand_key(64))

    return redirect(url_for("encrypt_des"))

# DES Encryption page
@app.route('/des-encrypt', methods=('GET', 'POST'))
def encrypt_des():
    global cipher_text
    global cipher_text_blocks
    global rkb

    # Get plain text from the text box
    if request.method == 'POST':
        cipher_text = ""
        plain_text = request.form['message']
        # start timer
        tic = time.perf_counter()

        hex_text = DES.text2hex(plain_text)
        blocks = DES.make_blocks(hex_text)

        rkb = DES.first_perm(des_key)
        cipher_text_blocks = []
        for block in blocks:
            cipher = DES.bin2hex(DES.encrypt(block, rkb))
            cipher_text_blocks.append(cipher)
            cipher_text = cipher_text + cipher

        # end timer
        toc = time.perf_counter()
        print(f"Encrypted the message in {toc - tic:0.4f} seconds")

        return redirect(url_for('decrypt_des'))

    return render_template('DES-encrypt.html', key = des_key)


# DES Decryption page
@app.route('/des-decrypt', methods=('GET', 'POST'))
def decrypt_des():
    global cipher_text
    global cipher_text_blocks
    global rkb
    decrypted = False
    orig_text = ""

    if request.method == 'POST':
        key = request.form['key']
        try:
            rkb = DES.first_perm(key)
            decrypted = True
            # start timer
            tic = time.perf_counter()
            rkb_rev = rkb[::-1]
            text = ""
            for block in cipher_text_blocks:
                text = text + DES.bin2hex(DES.encrypt(block, rkb_rev))

            orig_text = DES.hex2text(text)
        except:
            alert = True
            decrypted = False
            return render_template('DES-decrypt.html', cipher_text=cipher_text, orig_text=orig_text,
                                   decrypted=decrypted, alert = alert)

        # end timer
        toc = time.perf_counter()
        print(f"Decrypted the message in {toc - tic:0.4f} seconds")

    return render_template('DES-decrypt.html', cipher_text = cipher_text, orig_text = orig_text, decrypted = decrypted)

# MD5 Encryption page
@app.route('/md5-encrypt', methods=('GET', 'POST'))
def encrypt_md5():
    global digital_signature
    global plain_text
    # Get plain text from the box
    if request.method == 'POST':
        plain_text = request.form['message']
        # start timer
        tic = time.perf_counter()
        pt = bytes(plain_text, 'utf-8')
        digital_signature = md5.to_hex(md5.encrypt(pt))

        # end timer
        toc = time.perf_counter()
        print(f"Encrypted the message in {toc - tic:0.4f} seconds")

        return redirect(url_for('decrypt_md5'))

    return render_template('md5-encrypt.html')


# MD5 Decryption page
@app.route('/md5-decrypt', methods=('GET', 'POST'))
def decrypt_md5():
    global digital_signature
    global plain_text
    verify = False

    digital_signature2 = digital_signature
    # Get plain text from the box
    if request.method == 'POST':
        verify = True
        plain_text2 = request.form['message']
        tic = time.perf_counter()
        pt = bytes(plain_text2, 'utf-8')
        digital_signature2 = md5.to_hex(md5.encrypt(pt))

        # end timer
        toc = time.perf_counter()
        print(f"Decrypted the message in {toc - tic:0.4f} seconds")


    return render_template('md5-decrypt.html', digital_signature = digital_signature, digital_signature2 = digital_signature2, plain_text = plain_text, verify = verify )

# RSA encryption page
@app.get("/rsa")
def rsa():
    global encryptionRedirected
    global decryptionRedirected
    publicKeyString = "({}, {})".format(public[0], public[1])
    privateKeyString = "({}, {})".format(private[0], private[1])
    if not encryptionRedirected and not decryptionRedirected:
        return render_template("RSA.html", publicKey = publicKeyString, privateKey = privateKeyString, 
            encrypted = "Your encrypted mesage will be displayed here",
            decrypted = "Your decrypted message will be displayed here")
    elif not decryptionRedirected:
        encryptionRedirected = False
        encryptedString = ''.join(map(lambda x: str(x), encrypted))
        return render_template("RSA.html", publicKey = publicKeyString, privateKey = privateKeyString, encrypted = encryptedString,
            decrypted = "Your decrypted message will be displayed here")
    else:
        encryptedString = ''.join(map(lambda x: str(x), encrypted)) 
        return render_template("RSA.html", publicKey = publicKeyString, privateKey = privateKeyString, encrypted = encryptedString, decrypted = decrypted)

# Runs when clicking the generate new primes button
@app.get("/rsa/generate")
def generate():
    global public
    global private
    public, private = generate_keypair(generate_prime(), generate_prime())
    return redirect(url_for("rsa"))

# Runs when they click the encrypt button
@app.post("/rsa/encrypt")
def encryptmessage():
    global encryptionRedirected
    global encrypted
    encryptionRedirected = True
    # start timer
    tic = time.perf_counter()
    encrypted = encrypt(private, request.form.get("message"))
    # end timer
    toc = time.perf_counter()
    print(f"Encrypted the message in {toc - tic:0.4f} seconds")
    return redirect(url_for("rsa"))

# Runs when they click the decrypt button
@app.post("/rsa/decrypt")
def decryptmessage():
    global decryptionRedirected
    global decrypted
    # start timer
    tic = time.perf_counter()
    decrypted = decrypt(public, encrypted)
    # end timer
    toc = time.perf_counter()
    print(f"Decrypted the message in {toc - tic:0.4f} seconds")
    decryptionRedirected = True
    return redirect(url_for("rsa"))

@app.route('/vigenereCipher', methods = ["GET", "POST"])
def vc_encrypt():
    encryptedMessage = ""
    currentKey = ""
    if request.method == "POST":
        message = request.form.get("message")
        messages.append(message)
        keyword = request.form.get("keyword")
        # start timer
        tic = time.perf_counter()
        currentKey = vigenereCipher.createKey(message, keyword)
        encryptedMessage = vigenereCipher.encrypt(message, currentKey)

        # end timer
        toc = time.perf_counter()
        print(f"Encrypted the message in {toc - tic:0.4f} seconds")
      #  return vigenereCipher.encrypt(message, vigenereCipher.createKey(message, keyword))
    return render_template('vigCipherEncrypt.html', msg=encryptedMessage, key=currentKey)

@app.route('/vigenereCipherDecrypt', methods = ["GET", "POST"])
def vc_decrypt():
    decryptedMessage = ""
    key = ""
    if request.method == "POST":
        encryptedMessage = request.form.get("message")
        originalMessage = messages[-1]
        keyword = request.form.get("keyword")
        # start timer
        tic = time.perf_counter()
        key = vigenereCipher.createKey(originalMessage, keyword)
        decryptedMessage = vigenereCipher.decrypt(encryptedMessage, key)

        # end timer
        toc = time.perf_counter()
        print(f"Decrypted the message in {toc - tic:0.4f} seconds")
    return render_template('vigCipherDecrypt.html', decryptMsg=decryptedMessage)


if __name__ == '__main__':
   app.run()

