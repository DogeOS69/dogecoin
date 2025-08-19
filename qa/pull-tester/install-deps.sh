#!/bin/bash

# installs test dependencies
# Python 3.12+ compatible packages
python3 -m pip install scrypt pyasyncore zmq --break-system-packages
echo "Installed Python 3.12 compatible test dependencies"
