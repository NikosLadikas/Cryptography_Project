from flask import Flask, render_template, request
from crypto_utils import generate_keys, encrypt_message, decrypt_message, sign_message, verify_signature

app = Flask(__name__)

private_key, public_key = generate_keys()

@app.route("/", methods=["GET", "POST"])
def index():
    encrypted_message = decrypted_message = signature = verification_result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message")

        if "encrypt" in request.form:
            encrypted_message = encrypt_message(message, public_key)

        elif "decrypt" in request.form:
            encrypted_message = request.form.get("encrypted_message")
            decrypted_message = decrypt_message(encrypted_message, private_key)

        elif "sign" in request.form:
            signature = sign_message(message, private_key)

        elif "verify" in request.form:
            signature = request.form.get("signature")
            verification_result = verify_signature(message, signature, public_key)

    return render_template("index.html", public_key=public_key, private_key=private_key,
                           encrypted_message=encrypted_message, decrypted_message=decrypted_message,
                           signature=signature, verification_result=verification_result, message=message)

if __name__ == "__main__":
    app.run(debug=True)
