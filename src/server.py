import socket, threading, json, base64, struct, datetime
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15

# Global variables to store expected client count, connected client sockets, and certificates.
expected_clients = 3
clients = {}      # Maps client subject to its socket.
certificates = {} # Maps client subject to its certificate.


# --- Data Input output utility methods ---------------------------------------
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

# Serialize a dictionary to JSON, prefix it with its length, and send over the socket.
def send_msg(sock, message_dict):
    message = json.dumps(message_dict).encode("utf-8")
    sock.sendall(struct.pack("!I", len(message)) + message)
#---------------------------------------------------------------------------------------

# --- loading key and certificates -------------------------------------------
# Load a certificate from a JSON file.
def load_cert(filename):
    with open(f"certificates/{filename}", "r", encoding="utf-8") as f:
        return json.load(f)

# Load a private key from a PEM file.
def load_private_key(filename):
    with open(f"certificates/{filename}", "rb") as f:
        return f.read()

# Load root CA certificate and server's certificate/private key.
root_ca_cert = load_cert("RootCA.json")
server_cert = load_cert("ChatServer.json")
server_private_key = load_private_key("ChatServer.pem")
print("[SERVER] Certificates and keys loaded.")
#-----------------------------------------------------------------------------------

# --- Certificate verification ------------------------------------------------------
# Verify the certificate's validity period and digital signature using the Root CA.
def verify_cert(cert):
    try:
        now = str(datetime.datetime.now(datetime.UTC))
        if cert["valid_from"] > now or cert["valid_to"] < now:
            print("[SERVER] Certificate expired or not yet valid.")
            return False
        root_pub = RSA.import_key(base64.b64decode(root_ca_cert["public_key"]))
        h = SHA256.new(cert["signed_json"].encode())
        sig = base64.b64decode(cert["signature"])
        pkcs1_15.new(root_pub).verify(h, sig)
        return True
    except Exception as e:
        print(f"[SERVER] Certificate verification failed: {e}")
        return False
#------------------------------------------------------------------------------------

# --- Broadcast utility ------------------------------------------------
# Send a message to all connected clients, optionally excluding one.
def send_message_Allclients(message, exclude=None):
    for user, sock in clients.items():
        if user != exclude:
            try:
                send_msg(sock, message)
            except:
                pass
#---------------------------------------------------------------------------------

# --- Client connections ---------------------------------------------------------
# Handle the lifecycle of an individual client connection.
def client_connections(sock):
    subject = None
    try:
        # Receive and verify the client's certificate.
        cert = recv_msg(sock)
        subject = cert.get("subject")
        if verify_cert(cert):
            clients[subject] = sock
            certificates[subject] = cert  # Store the verified certificate.
            print(f"[SERVER] {subject} authenticated and certificate stored.")
            # Respond with AUTH_SUCCESS and include the server's certificate for mutual verification.
            send_msg(sock, {"status": "AUTH_SUCCESS", "server_cert": server_cert})

            # If all expected clients are connected, notify them to start key exchange.
            if len(clients) == expected_clients:
                send_message_Allclients({"type": "start_key"})
                print("[SERVER] All clients authenticated. start_key signal sent.")

            # Continuously handle incoming messages from the client.
            while True:
                msg = recv_msg(sock)
                if msg is None:
                    break

                # Process certificate requests from the client.
                if msg.get("type") == "cert_request":
                    requested_subject = msg.get("requested_subject")
                    if requested_subject:
                        requested_cert = certificates.get(requested_subject)
                        if requested_cert:
                            send_msg(sock, {"type": "cert_response", "certificate": requested_cert})
                        else:
                            send_msg(sock, {"type": "cert_response", "error": "Certificate not found"})
                    else:
                        send_msg(sock, {"type": "cert_response", "certificates": certificates})
                    continue

                # Broadcast the received message to all other clients.
                send_message_Allclients(msg, exclude=subject)
        else:
            send_msg(sock, {"status": "AUTH_FAILED"})
    except Exception as e:
        print(f"[SERVER] Error with {subject}: {e}")
    finally:
        # Clean up client data on disconnection.
        if subject in clients:
            del clients[subject]
        if subject in certificates:
            del certificates[subject]
        sock.close()
#-------------------------------------------------------------------------

# --- Start server -------------------------------------------------------------
# Initialize the server socket, bind to host/port, and accept incoming client connections.
def start_server(host="127.0.0.1", port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[SERVER] Listening on {host}:{port}")
    while True:
        client, _ = server.accept()
        threading.Thread(target=client_connections, args=(client,), daemon=True).start()

start_server()
#--------------------------------------------------------------------------------------