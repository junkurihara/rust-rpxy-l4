#!/bin/bash

cleanup() { sudo kill "$PROXY_PID" "$BACKEND_PID" "$TSHARK_PID" 2>/dev/null || true; }
trap cleanup EXIT

set -e

echo "Starting E2E ECH Testing..."

# ==========================================
# SETUP
# ==========================================

# Start the Backend Server
sudo ./target/release/tlsserver-mio --certs ./examples/server.crt --key ./examples/server.key --verbose http &
BACKEND_PID=$!

# Start rpxy-l4
RUST_LOG=debug ./target/release/rpxy-l4 --config e2e.config.toml > /tmp/proxy.log 2>&1 &
PROXY_PID=$!

echo "Waiting for Proxy to bind to port 8448..."
for i in {1..20}; do
    if bash -c "</dev/tcp/127.0.0.1/8448" 2>/dev/null; then
        echo "Proxy is ready!"
        break
    fi
    sleep 0.5
    if [ "$i" -eq 20 ]; then
        echo "❌ FATAL: Timeout waiting for proxy to start."
        exit 1
    fi
done

sudo rm -f /tmp/e2e_capture.pcap 2>/dev/null || true

# Start tshark capturing
sudo tshark -i any -f "tcp port 8448" -w /tmp/e2e_capture.pcap -a duration:6 > /dev/null 2>&1 &
TSHARK_PID=$!

echo "Waiting for packet capturing..."
for i in {1..10}; do
    if [ -f /tmp/e2e_capture.pcap ]; then
        echo "tshark capture done!"
        break
    fi
    sleep 0.5
    if [ "$i" -eq 10 ]; then
        echo "❌ FATAL: Timeout waiting for tshark."
        exit 1
    fi
done

sleep 1

# ==========================================
# EXECUTION & VERIFICATION
# ==========================================
echo "Sending Encrypted ClientHello..."

# Run the client
set +e
CLIENT_OUTPUT=$(./target/release/ech-client --host localhost --cafile ./examples/server.crt public.example localhost 2>&1)
CLIENT_EXIT_CODE=$?
set -e


# Waiting for tshark to finish up
wait $TSHARK_PID || true
echo "Capture finished. Saved to e2e_capture.pcap."

if [ -f /tmp/e2e_capture.pcap ]; then
    #sudo chown $(whoami):$(whoami) /tmp/e2e_capture.pcap || true
    sudo chown $(whoami) /tmp/e2e_capture.pcap || true
else
    echo "❌ FATAL: e2e_capture.pcap not found."
    exit 1
fi

# ----------------- Assertions ----------------- 
echo "Verifying ECH Acceptance..."

TEST_RESULT=0

# Check 1: Did the TLS connection succeed at all?
if [ $CLIENT_EXIT_CODE -ne 0 ]; then
    echo "❌ FAILED: Client failed to connect."
    TEST_RESULT=1
else
    echo "✅ PASSED: ECH accepted by the backend."
fi

# Check 2: Did the proxy successfully decrypt the packet?
if grep -q "Decryption succeeded" /tmp/proxy.log; then
    echo "✅ PASSED: ECH Decryption Succeeded."
else
    echo "❌ FAILED: ECH Decryption Failed."
    TEST_RESULT=1
fi


# Reading the capture packets...

# Check 3: Was the ClientHello sent?
CLIENT_ECH=$(tshark -r /tmp/e2e_capture.pcap -d tcp.port==8448,tls -Y "tcp.port==8448 && tls.handshake.type == 1 && tls.handshake.extension.type == 65037" 2>/dev/null) || true

if [ -z "$CLIENT_ECH" ]; then
    echo "❌ FAILED: No ClientHello found. The Client did not send the ECH extension."
    TEST_RESULT=1
else
    echo "✅ PASSED: ClientHello detected. Client successfully sent ECH."
fi

# Check 4: Did the packet reached the backend server?
SERVER_REPLY=$(tshark -r /tmp/e2e_capture.pcap -d tcp.port==8448,tls -Y "tcp.port==8448 && tls.handshake.type == 2" 2>/dev/null) || true

if [ -z "$SERVER_REPLY" ]; then
    echo "❌ FAILED: No ServerHello found. The connection was dropped by the proxy or backend."
    TEST_RESULT=1
else
    echo "✅ PASSED: ServerHello received."
fi

# Check 5: Did the inner SNI really hidden?
OUTER_SNI=$(tshark -r /tmp/e2e_capture.pcap -d tcp.port==8448,tls -Y "tcp.port==8448 && tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null) || true

if [[ "$OUTER_SNI" == *"public.example"* ]] && [[ "$OUTER_SNI" != *"localhost"* ]]; then
    echo "✅ PASSED: Outer SNI appeared. Inner SNI is hidden."
else
    echo "❌ FAILED: Inner SNI leaked or did not match cover name. Found: $OUTER_SNI"
    TEST_RESULT=1
fi

# Output the overall test result
if (( TEST_RESULT == 0 )); then
    echo "E2E Testing Passed."
else
    echo "E2E Testing Failed."
fi


# Exit with the test result (0 = GitHub Action Pass, 1 = GitHub Action Fail)
exit $TEST_RESULT
