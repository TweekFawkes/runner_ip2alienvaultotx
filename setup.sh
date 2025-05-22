#! /bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3
sudo apt-get install -y python3-pip
sudo apt-get install -y python-is-python3

python3 -m pip install -r requirements.txt

# Install dnsutils
# apt install -y netbase
# apt install -y whois
# sudo apt-get install -y whois
