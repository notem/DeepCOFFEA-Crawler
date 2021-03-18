#!/bin/bash

# configures and runs a crawl (inside a docker container)
# IMPORTANT: If this file is changed, docker container needs to be rebuilt

# globals
PYTHON_VERSION='python3'
PYTHON_PATH=`which $PYTHON_VERSION`
BASE='/home/docker/corrcrawl'

# set offloads
#ifconfig $2 mtu 1500
ip link set dev $2 mtu 1500
ethtool -K $2 tx off rx off tso off gso off gro off lro off

# set base directory
pushd ${BASE}

# re-install python requirements
# this step is only necessary if you've updated the requirements since building
#pip install -U -r requirements.txt

# copy tor browser bundle
rm -rf tor-browser_en-US
cp -r /home/docker/tbb_setup/tor-browser_en-US .

# TODO: do other stuff here if you need to
mkdir ~/.ssh
echo "Host *
    StrictHostKeyChecking no" > ~/.ssh/config

# Run command with params
$PYTHON_PATH $1
