from flask import Flask, render_template, request, redirect, url_for, flash
import DES, md5
from RSA import *

app = Flask(__name__)

# DES global variables
cipher_text = ""
cipher_text_blocks = []
rk = []
rkb = []

# MD5 global variables
digital_signature = ""
plain_text = ""

# RSA global variables
public, private = generate_keypair(generate_prime(), generate_prime())
encryptionRedirected = False
decryptionRedirected = False

# Home page
@app.route('/')
def home():
    return render_template('home.html')


# DES Encryption page
@app.route('/des-encrypt', methods=('GET', 'POST'))
def encrypt_des():
    global cipher_text
    global cipher_text_blocks
    global rk
    global rkb
    # Get plain text from the box
    if request.method == 'POST':
        cipher_text = ""
        plain_text = request.form['message']
        if not plain_text:
            flash('Type a message to encrypt')
        else:
            hex_text = DES.text2hex(plain_text)
            blocks = DES.make_blocks(hex_text)

            key = DES.bin2hex(DES.rand_key(64))
            [rkb, rk] = DES.first_perm(key)
            cipher_text_blocks = []
            block_num = 0
            for block in blocks:
                block_num = block_num + 1
                cipher = DES.bin2hex(DES.encrypt(block, rkb, rk, block_num))
                cipher_text_blocks.append(cipher)
                cipher_text = cipher_text + cipher
        return redirect(url_for('decrypt_des'))

    return render_template('DES-encrypt.html')


# DES Encryption page
@app.route('/des-decrypt', methods=('GET', 'POST'))
def decrypt_des():
    global cipher_text
    global cipher_text_blocks
    global rkb
    global rk
    decrypted = False
    orig_text = ""

    if request.method == 'POST':
        decrypted = True
        rkb_rev = rkb[::-1]
        rk_rev = rk[::-1]
        text = ""
        block_num = 0
        for block in cipher_text_blocks:
            block_num = block_num + 1
            text = text + DES.bin2hex(DES.encrypt(block, rkb_rev, rk_rev, block_num))

        orig_text = DES.hex2text(text)

    return render_template('DES-decrypt.html', cipher_text = cipher_text, orig_text = orig_text, decrypted = decrypted)

# MD5 Encryption page
@app.route('/md5-encrypt', methods=('GET', 'POST'))
def encrypt_md5():
    global digital_signature
    global plain_text
    # Get plain text from the box
    if request.method == 'POST':
        plain_text = request.form['message']
        if not plain_text:
            flash('Type a message to encrypt')
        else:
            pt = bytes(plain_text, 'utf-8')
            digital_signature = md5.md5_to_hex(md5.md5(pt))

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
        if not plain_text2:
            flash('Type a message to encrypt')
        else:
            pt = bytes(plain_text2, 'utf-8')
            digital_signature2 = md5.md5_to_hex(md5.md5(pt))


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
    encrypted = encrypt(private, request.form.get("message"))
    return redirect(url_for("rsa"))

# Runs when they click the decrypt button
@app.post("/rsa/decrypt")
def decryptmessage():
    global decryptionRedirected
    global decrypted
    decrypted = decrypt(public, encrypted)
    decryptionRedirected = True
    return redirect(url_for("rsa"))


if __name__ == '__main__':
   app.run()

