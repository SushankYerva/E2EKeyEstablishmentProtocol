import socket, json, base64, sys, threading, time, hashlib, struct, datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Signature import pkcs1_15  # For digital signatures
from Cryptodome.Random import get_random_bytes

cert_cache = {}  # Store fetched peer certificates
# --- input output utility methods----------------------------------------------------
# Receive exactly n bytes from the socket.
def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Read a 4-byte length header and then receive the complete JSON message.
def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack("!I", raw_len)[0]
    data = recvall(sock, length)
    return json.loads(data.decode("utf-8"))

# Serialize a dictionary to JSON, prefix with its length, and send over the socket.
def send_msg(sock, message_dict):
    message = json.dumps(message_dict).encode("utf-8")
    sock.sendall(struct.pack("!I", len(message)) + message)
#----------------------------------------------------------------------------------------------

def request_certificate(sock, target_name):
    if target_name in cert_cache:
        return cert_cache[target_name]
    send_msg(sock, {"type": "cert_request", "requested_subject": target_name})
    resp = recv_msg(sock)
    if resp and "certificate" in resp:
        cert_cache[target_name] = resp["certificate"]
        return cert_cache[target_name]
    else:
        print(f"[{client_name}] Failed to get certificate for {target_name}")
        return None

# --- Command-line argument check -----------------------------------
if len(sys.argv) != 2:
    sys.exit("Usage: python client.py <ClientName> Ex: ClientA")
client_name = sys.argv[1]  # Set the client's name based on command-line argument.

# --- Load certificate and private key -------------------------------------
# Load a certificate from a JSON file in the certificates directory.
def load_cert(filename):
    with open(f"certificates/{filename}", "r", encoding="utf-8") as f:
        return json.load(f)

# Load a private key from a PEM file in the certificates directory.
def load_private_key(filename):
    with open(f"certificates/{filename}", "rb") as f:
        return f.read()

try:
    cert = load_cert(f"{client_name}.json")
    rsa_private = load_private_key(f"{client_name}.pem")
    now = str(datetime.datetime.now(datetime.UTC))
    # Ensure the certificate is within its valid time window.
    if cert["valid_from"] > now or cert["valid_to"] < now:
        sys.exit(f"[{client_name}] Certificate is not valid.")
    print(f"[{client_name}] Loaded certificate and RSA key.")
except Exception as e:
    sys.exit(f"[{client_name}] Cert/key load error: {e}")
#-------------------------------------------------------------------------------------

# --- Function to verify a certificate using the Root CA ---
# Verify the provided certificate using the Root CA and its validity period.
def verify_certificate(cert_to_verify):
    try:
        root_ca_cert = load_cert("RootCA.json")
        now = str(datetime.datetime.now(datetime.UTC))
        if cert_to_verify["valid_from"] > now or cert_to_verify["valid_to"] < now:
            print(f"[{client_name}] Certificate is not valid (expired or not yet valid).")
            return False
        root_pub = RSA.import_key(base64.b64decode(root_ca_cert["public_key"]))
        h = SHA256.new(cert_to_verify["signed_json"].encode())
        sig = base64.b64decode(cert_to_verify["signature"])
        pkcs1_15.new(root_pub).verify(h, sig)
        return True
    except Exception as e:
        print(f"[{client_name}] Certificate verification failed: {e}")
        return False
# --------------------------------------------------------------------------------------------

# --- Send client's certificate and verify server certificate ----------------------------------
# Send the client's certificate to the server and wait for a response with the server's certificate.
def send_cert(sock):
    send_msg(sock, cert)
    resp = recv_msg(sock)
    if resp.get("status") == "AUTH_SUCCESS" and "server_cert" in resp:
        server_cert = resp["server_cert"]
        if verify_certificate(server_cert):
            print(f"[{client_name}] Server certificate verified.")
            return True
        else:
            print(f"[{client_name}] Server certificate verification failed.")
            return False
    else:
        return False
#--------------------------------------------------------------------------------------------------

# --- Authenticated Integrity checks for key exchange --------------------------------------------
# Sign the concatenation of the client name and the key contribution.
def sign_contribution(contribution):
    msg_to_sign = (client_name + contribution).encode()
    h = SHA256.new(msg_to_sign)
    priv_key_obj = RSA.import_key(rsa_private)
    signature = pkcs1_15.new(priv_key_obj).sign(h)
    return base64.b64encode(signature).decode()

# Verify the digital signature from the sender using the sender's public key.
def verify_signature(sock, sender, contribution, signature):
    try:
        peer_cert = request_certificate(sock, sender)
        if not peer_cert:
            return False
        peer_pub = RSA.import_key(base64.b64decode(peer_cert["public_key"]))
        msg_to_sign = (sender + contribution).encode()
        h = SHA256.new(msg_to_sign)
        pkcs1_15.new(peer_pub).verify(h, base64.b64decode(signature))
        return True
    except Exception as e:
        print(f"[{client_name}] Signature verification error from {sender}: {e}")
        return False
#-----------------------------------------------------------------------------------------------------

# --- Group Key -------------------------------------------------
my_random = get_random_bytes(16)  # Generate random bytes for the key contribution.
my_contribution = my_random.hex()   # Convert the random bytes to a hex string.
key_contributions = {client_name: my_contribution}  # Store our own key contribution.
group_key = None  # Placeholder for the final group key.
expected_clients = 3
start_key_received = False


def send_key_share(sock, recipient):
    try:
        peer_cert = request_certificate(sock, recipient)
        if not peer_cert:
            return
        peer_pub = RSA.import_key(base64.b64decode(peer_cert["public_key"]))
        cipher = PKCS1_OAEP.new(peer_pub)
        enc = cipher.encrypt(my_contribution.encode())
        sig = sign_contribution(my_contribution)
        msg = {
            "type": "key_share",
            "sender": client_name,
            "recipient": recipient,
            "contribution": base64.b64encode(enc).decode(),
            "signature": sig
        }
        send_msg(sock, msg)
    except Exception as e:
        print(f"[{client_name}] Error sending to {recipient}: {e}")
# ----------------------------------------------------------------------------------------------

# ------- encryption and decryption ------------------------------------
# Encrypt a plaintext message using AES GCM and compute an HMAC for integrity.
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(message.encode())
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message.encode())
    return {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "tag": base64.b64encode(tag).decode(),
        "hmac": h.hexdigest()
    }

# Decrypt a message encrypted with AES GCM and verify its HMAC for integrity.
def decrypt_message(msg, key):
    try:
        nonce = base64.b64decode(msg["nonce"])
        ct = base64.b64decode(msg["ciphertext"])
        tag = base64.b64decode(msg["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag).decode()
        h = HMAC.new(key, digestmod=SHA256)
        h.update(plaintext.encode())
        return plaintext if h.hexdigest() == msg["hmac"] else "[HMAC ERROR] Integrity compromised."
    except Exception as e:
        return f"[DECRYPTION ERROR] {e}"
# ------------------------------------------------------------------------------

#-----------processing incoming messages and group key formation ---------------------------------------
def incoming_messages(sock):
    # Continuously process incoming messages from the server.
    global group_key, start_key_received
    while True:
        try:
            msg = recv_msg(sock)
            if msg is None:
                continue
            typ = msg.get("type")
            # If a start_key signal is received, broadcast our key contribution.
            if typ == "start_key":
                start_key_received = True
                peers = msg.get("clients", ["A", "B", "C"])
                peers = [p for p in peers if p != client_name]
                for peer in peers:
                    cert = request_certificate(sock, peer)
                    if cert:
                        print(f"[{client_name}] Fetched cert for {peer}")
                    else:
                        print(f"[{client_name}] Failed to get certificate for {peer}")
                        return
                for peer in peers:
                    send_key_share(sock, peer)
            elif typ == "key_share":
                # Process a key share message, decrypt if it is addressed to us.
                if "recipient" in msg and msg["recipient"] != client_name:
                    continue
                try:
                    if "recipient" in msg:
                        cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private))
                        dec = cipher.decrypt(base64.b64decode(msg["contribution"])).decode()
                    else:
                        dec = msg["contribution"]
                    # Verify the attached digital signature of the key share.
                    if "signature" in msg:
                        if not verify_signature(sock, msg["sender"], dec, msg["signature"]):
                            print(f"[{client_name}] Invalid signature from {msg['sender']}. Ignoring key share.")
                            continue
                    else:
                        print(f"[{client_name}] No signature provided by {msg['sender']}. Ignoring key share.")
                        continue
                    key_contributions[msg["sender"]] = dec
                except Exception as e:
                    print(f"[{client_name}] Key share error from {msg['sender']}: {e}")
            elif typ == "cert_response":
                subject = msg.get("subject")
                if subject and "certificate" in msg:
                    with open(f"certificates/{subject}.json", "w", encoding="utf-8") as f:
                        json.dump(msg["certificate"], f, indent=4)
                    print(f"[{client_name}] Received and saved certificate for {subject}.")
            elif typ == "group_chat":
                # Decrypt and display the received group chat message.
                sender = msg.get("sender")
                text = decrypt_message(msg, group_key)
                print(f"\n[{sender}]: {text}")

            # ----------Group key formation---------------------------------------------------------------
            # Once all key contributions are received, derive the final group key.
            if group_key is None and len(key_contributions) >= expected_clients:
                sorted_keys = [key_contributions[name] for name in sorted(key_contributions)]
                group_key = hashlib.sha256("".join(sorted_keys).encode()).digest()
                print(f"[{client_name}] Group key established.")
            # ----------------------------------------------------------------------------------------------
        except Exception as e:
            print(f"[{client_name}] Error: {e}")
            break
#---------------------------------------------------------------------------------------------------------

#----------- group chat session-------------------------------------
def group_chat_session(sock):
    # Start the incoming message handler thread and enter the chat message loop.
    global group_key
    threading.Thread(target=incoming_messages, args=(sock,), daemon=True).start()
    print(f"[{client_name}] Waiting for start_key...")
    while not start_key_received:
        time.sleep(0.5)
    time.sleep(3)
    # Continuously read user input and send encrypted group chat messages.
    while True:
        text = input("Enter group message: ").strip()
        if not text or group_key is None:
            continue
        enc_msg = encrypt_message(text, group_key)
        enc_msg.update({"type": "group_chat", "sender": client_name})
        send_msg(sock, enc_msg)
#-------------------------------------------------------------------------------------------

#--------- Initialize and start client --------------------------------------------
# Establish a connection to the server and initiate the mutual certificate handshake.
def start_client(host="127.0.0.1", port=5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(f"[{client_name}] Connected to server.")
    if send_cert(s):
        group_chat_session(s)
    else:
        print(f"[{client_name}] Authentication failed.")
        s.close()

start_client()
#---------------------------------------------------------------------------------------------