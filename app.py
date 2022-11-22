from flask import Flask, render_template, request, redirect, url_for
from RSA import *

app = Flask(__name__)

public, private = generate_keypair(generate_prime(), generate_prime())
encryptionRedirected = False
decryptionRedirected = False
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



@app.get("/rsa/generate")
def generate():
    global public
    global private
    public, private = generate_keypair(generate_prime(), generate_prime())
    return redirect(url_for("rsa"))

@app.post("/rsa/encrypt")
def encryptmessage():
    global encryptionRedirected
    global encrypted
    encryptionRedirected = True
    encrypted = encrypt(private, request.form.get("message"))
    return redirect(url_for("rsa"))

@app.post("/rsa/decrypt")
def decryptmessage():
    global decryptionRedirected
    global decrypted
    decrypted = decrypt(public, encrypted)
    decryptionRedirected = True
    return redirect(url_for("rsa"))