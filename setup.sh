#!/bin/sh

sudo useradd -d $(pwd) -M judge

mkdir -p container/standard
./build-container.sh container/standard
