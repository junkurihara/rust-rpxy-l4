#!/bin/bash

set -e

echo "Starting E2E ECH Testing..."

# ==========================================
# SETUP
# ==========================================

# Start the Backend Server
sudo ./target/release/tlsserver-mio --certs ./examples/server.crt --key ./examples/server.key --verbose http &
BACKEND_PID=$!

# Start rpxy-l4
#sudo ./target/release/rpxy-l4 --config e2e.config.toml &
RUST_LOG=debug ./target/release/rpxy-l4 --config e2e.config.toml > /tmp/proxy.log 2>&1 &
PROXY_PID=$!

sleep 2

sudo tshark -i lo -w /tmp/e2e_capture.pcap -a duration:6 > /dev/null 2>&1 &
TSHARK_PID=$!

sleep 1

# ==========================================
# EXECUTION & VERIFICATION
# ==========================================
echo "Sending Encrypted ClientHello..."

# Run the client
set +e
CLIENT_OUTPUT=$(./target/release/ech-client --host localhost --cafile ./examples/server.crt localhost localhost 2>&1)
CLIENT_EXIT_CODE=$?
set -e


# Waiting for tshark to finish up
wait $TSHARK_PID || true
echo "Capture timer finished. Saved to e2e_capture.pcap."

if [ -f /tmp/e2e_capture.pcap ]; then
    sudo chown $(whoami):$(whoami) /tmp/e2e_capture.pcap || true
else
    echo "❌ FATAL: e2e_capture.pcap not found."
    sudo kill $PROXY_PID $BACKEND_PID
    exit 1
fi

# ----------------- Assertions ----------------- 
echo "Verifying ECH Acceptance..."

TEST_RESULT=0

# Check 1: Did the TLS connection succeed at all?
if [ $CLIENT_EXIT_CODE -ne 0 ]; then
    echo "❌ FAILED: Client failed to connect."
    kill $PROXY_PID $BACKEND_PID
    exit 1
else
    echo "✅ PASSED: ECH accepted by the backend."
fi

# Check 2: Did the proxy successfully decrypt the packet?
if echo "$CLIENT_OUTPUT" | grep -q "Decryption succeeded" /tmp/proxy.log; then
    echo "✅ PASSED: ECH Decryption Succeeded."
else
    echo "❌ FAILED: ECH Decryption Failed."
    TEST_RESULT=1
fi


# Reading the capture packets...

# Check 3: Was the ClientHello sent?
CLIENT_ECH=$(tshark -r /tmp/e2e_capture.pcap -Y "tls.handshake.type == 1 && tls.handshake.extension.type == 65037" 2>/dev/null)

if [ -z "$CLIENT_ECH" ]; then
    echo "❌ FAILED: No ClientHello found. The Client did not send the ECH extension."
    TEST_RESULT=1
else
    echo "✅ PASSED: ClientHello detected. Client successfully sent ECH."
fi

# Check 4: Did the packet reached the backend server?
SERVER_REPLY=$(tshark -r /tmp/e2e_capture.pcap -Y "tls.handshake.type == 2" 2>/dev/null)

if [ -z "$SERVER_REPLY" ]; then
    echo "❌ FAILED: No ServerHello found. The connection was dropped by the proxy or backend."
    TEST_RESULT=1
else
    echo "✅ PASSED: ServerHello received."
fi

# Output the overall test result
if (( TEST_RESULT == 0 )); then
    echo "E2E Testing Passed."
else
    echo "E2E Testing Failed."
fi

# ==========================================
# TEARDOWN
# ==========================================
echo "Cleaning up processes..."

sudo kill $PROXY_PID $BACKEND_PID

# Exit with the test result (0 = GitHub Action Pass, 1 = GitHub Action Fail)
exit $TEST_RESULT
