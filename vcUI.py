from flask import Flask, render_template, request, g
import vigenereCipher

app = Flask(__name__)

messages = []

@app.route('/vigenereCipher', methods = ["GET", "POST"])
def encrypt():
    encryptedMessage = ""
    currentKey = ""
    if request.method == "POST":
        message = request.form.get("message")
        messages.append(message)
        keyword = request.form.get("keyword")
        currentKey = vigenereCipher.createKey(message, keyword)
        encryptedMessage = vigenereCipher.encrypt(message, currentKey)
      #  return vigenereCipher.encrypt(message, vigenereCipher.createKey(message, keyword))
    return render_template('vigCipherEncrypt.html', msg=encryptedMessage, key=currentKey)

@app.route('/vigenereCipherDecrypt', methods = ["GET", "POST"])
def decrypt():
    decryptedMessage = ""
    key = ""
    if request.method == "POST":
        encryptedMessage = request.form.get("message")
        originalMessage = messages[-1]
        keyword = request.form.get("keyword")
        key =  vigenereCipher.createKey(originalMessage, keyword)
        decryptedMessage = vigenereCipher.decrypt(encryptedMessage, key)
    return render_template('vigCipherDecrypt.html', decryptMsg=decryptedMessage)
      
if __name__=='__main__':
    app.run()