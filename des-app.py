from flask import Flask, render_template, request, redirect, url_for, flash
import DES

app = Flask(__name__)

cipher_text = ""
cipher_text_blocks = []
rk = []
rkb = []

# home-page
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

if __name__ == '__main__':
   app.run()

