import subprocess
import time
import pytest

@pytest.fixture(scope="module")
def start_server():
    # Start the server in a subprocess
    server = subprocess.Popen(["python", "src/server.py"])
    time.sleep(2)  # Wait a little to ensure the server starts properly
    yield server  # This is the server process, used in the test
    server.terminate()  # Cleanup: terminate the server after the test

def test_server_client_connection(start_server):
    # Run clients (A, B, C) in subprocesses
    client_a = subprocess.Popen(["python", "src/client.py", "A"])
    client_b = subprocess.Popen(["python", "src/client.py", "B"])
    client_c = subprocess.Popen(["python", "src/client.py", "C"])

    # Let the clients run for a while
    time.sleep(10)  # Adjust as needed for the client-server handshake

    # Check that all clients have started and established a key
    client_a_output = client_a.communicate(timeout=5)
    client_b_output = client_b.communicate(timeout=5)
    client_c_output = client_c.communicate(timeout=5)

    # Check that the output contains expected messages (e.g., "Group key established")
    assert "Group key established." in client_a_output[0].decode()
    assert "Group key established." in client_b_output[0].decode()
    assert "Group key established." in client_c_output[0].decode()
