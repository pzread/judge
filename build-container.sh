#/bin/bash

mkdir -p container/usr/lib
mkdir -p container/usr/bin
mkdir -p container/lib
mkdir -p container/lib64
mkdir -p container/compile
mkdir -p container/run

cp /usr/bin/g++ container/usr/bin/g++
cp /usr/bin/as container/usr/bin/as
cp /usr/bin/ld container/usr/bin/ld
cp /usr/lib/libopcodes-2.24-system.so container/usr/lib/libopcodes-2.24-system.so
cp /usr/lib/libbfd-2.24-system.so container/usr/lib/libbfd-2.24-system.so
cp -a /usr/lib/x86_64-linux-gnu container/usr/lib/x86_64-linux-gnu
cp -a /usr/lib/gcc container/usr/lib/gcc
cp -a /usr/include container/usr/include
cp -a /lib/x86_64-linux-gnu container/lib/x86_64-linux-gnu
cp -a /lib64/ld-linux-x86-64.so.2 container/lib64/ld-linux-x86-64.so.2
