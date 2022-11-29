from flask import Flask, render_template, request, redirect, url_for, flash
import DES, md5

app = Flask(__name__)

# DES global variables
cipher_text = ""
cipher_text_blocks = []
rk = []
rkb = []

# MD5 global variables
digital_signature = ""
plain_text = ""

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

            # print this to the page
            print("Performing encryption...")
            key = "AABB09182736CCDD"  # add key generation later
            [rkb, rk] = DES.first_perm(key)
            # # For printing entire cipher text
            # # For saving each block of cipher text so they can be decrypted by block later
            cipher_text_blocks = []
            block_num = 0
            for block in blocks:
                block_num = block_num + 1
                cipher = DES.bin2hex(DES.encrypt(block, rkb, rk, block_num))
                cipher_text_blocks.append(cipher)
                cipher_text = cipher_text + cipher
                # Send cipher text to the html and print it there when the button is clicked to encrypt
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




if __name__ == '__main__':
   app.run()

