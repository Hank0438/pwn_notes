FROM ubuntu:16.04

# Refresh local apt keys & update
RUN apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com \
    && apt-get update -qq

# add deadsnakes ppa
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update

# install python
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3.9 \
    python3.9-distutils


# Create a python3 symlink pointing to latest python version
RUN ln -sf /usr/bin/python3.9 /usr/bin/python3

# Install matching pip version
RUN apt install curl

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && python3.9 get-pip.py \
    && rm get-pip.py

RUN python3.9 -m pip install pwntools
