
import hashlib
import secrets
from flask import Flask, render_template, jsonify
import os


app = Flask(__name__)


filename = "bip-0039.txt"

def load_wordlist(filename):
    """Load the BIP39 wordlist from a given file."""
    with open(filename, 'r', encoding='utf-8') as f:
        words = [line.strip() for line in f if line.strip()]
    return words


word_list = load_wordlist(filename)


num_bytes = 32
entropy = secrets.token_bytes(32)

def generate_entropy(num_bytes):
    """Generate cryptographically secure random entropy."""
    return secrets.token_bytes(num_bytes)

def entropy_to_bits(entropy: bytes) -> str:
    """Convert entropy bytes to a string of bits."""
    return ''.join(format(byte, '08b') for byte in entropy)

def compute_checksum(entropy: bytes) -> str:
    hash_digest = hashlib.sha3_512(entropy).digest()
    checksum_length = len(entropy) * 8 // 32 
    hash_bits = ''.join(format(byte, '08b') for byte in hash_digest)
    return hash_bits[:checksum_length]



def generate_mnemonic(entropy: bytes, wordlist: list) -> str:
    entropy_bits = entropy_to_bits(entropy)
    checksum_bits = compute_checksum(entropy)
    full_bits = entropy_bits + checksum_bits

    # Each word corresponds to 11 bits.
    words = []
    for i in range(0, len(full_bits), 11):
        index = int(full_bits[i:i+11], 2)
        words.append(wordlist[index])
    return ' '.join(words)

mnemonic_phrase = generate_mnemonic(entropy,word_list)
print("Mnemonic Phrase:")
print(mnemonic_phrase)


def derive_wallet_seed(mnemonic: str, passphrase: str, dklen: int = 64) -> bytes:

    salt = ("mnemonic" + passphrase).encode('utf-8')
    # scrypt parameters: n=2**14, r=8, p=1
    seed = hashlib.scrypt(mnemonic.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=dklen)
    return seed
passphrase = "myStrongPassphrase"
wallet_seed = derive_wallet_seed(mnemonic_phrase, passphrase)
print("Derived Wallet Seed (hex):")
print(wallet_seed.hex())



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate", methods=["GET"])
def generate():
    try:
        entropy = generate_entropy(32)  # 32 bytes -> standard 24-word mnemonic
        wordlist = load_wordlist("bip-0039.txt")
        mnemonic = generate_mnemonic(entropy, wordlist)
        wallet_seed = derive_wallet_seed(mnemonic,passphrase)
        return jsonify({
            "mnemonic": mnemonic,
            "wallet_seed": wallet_seed.hex()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

