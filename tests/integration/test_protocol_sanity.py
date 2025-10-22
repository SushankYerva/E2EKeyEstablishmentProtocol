import subprocess
import time
from unittest import mock
import pytest

@pytest.fixture(scope="module")
def start_server():
    # Start the server in a subprocess
    server = subprocess.Popen(["python", "src/server.py"])
    time.sleep(2)  # Wait a little to ensure the server starts properly
    yield server  # This is the server process, used in the test
    server.terminate()  # Cleanup: terminate the server after the test

def test_server_client_connection(start_server):
    # Mock input() to simulate the clients entering messages
    with mock.patch("builtins.input", return_value="Test group message"):
        # Run clients (A, B, C) in subprocesses
        client_a = subprocess.Popen(["python", "src/client.py", "A"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        client_b = subprocess.Popen(["python", "src/client.py", "B"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        client_c = subprocess.Popen(["python", "src/client.py", "C"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Let the clients run for a while
        time.sleep(10)  # Adjust as needed for the client-server handshake

        # Check that all clients have started and established a key
        client_a_output, client_a_error = client_a.communicate(timeout=5)
        client_b_output, client_b_error = client_b.communicate(timeout=5)
        client_c_output, client_c_error = client_c.communicate(timeout=5)

        # Ensure no errors and check if the expected output is found
        assert client_a_output is not None, f"Client A failed: {client_a_error.decode()}"
        assert client_b_output is not None, f"Client B failed: {client_b_error.decode()}"
        assert client_c_output is not None, f"Client C failed: {client_c_error.decode()}"

        # Check that the output contains expected messages (e.g., "Group key established")
        assert "Group key established." in client_a_output.decode()
        assert "Group key established." in client_b_output.decode()
        assert "Group key established." in client_c_output.decode()
