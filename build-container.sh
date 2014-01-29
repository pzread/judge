#/bin/bash

mkdir -p $1/usr/lib
mkdir -p $1/usr/bin
mkdir -p $1/lib
mkdir -p $1/lib64
mkdir -p $1/tmp
mkdir -p $1/code
mkdir -p $1/run

cp /usr/bin/g++ $1/usr/bin/g++
cp /usr/bin/clang++ $1/usr/bin/clang++
cp /usr/bin/as $1/usr/bin/as
cp /usr/bin/ld $1/usr/bin/ld
cp /usr/lib/libopcodes-2.24-system.so $1/usr/lib/libopcodes-2.24-system.so
cp /usr/lib/libbfd-2.24-system.so $1/usr/lib/libbfd-2.24-system.so
cp -a /usr/lib/x86_64-linux-gnu $1/usr/lib/x86_64-linux-gnu
cp -a /usr/lib/gcc $1/usr/lib/gcc
cp -a /usr/lib/llvm-3.3 $1/usr/lib/llvm-3.3
cp -a /usr/include $1/usr/include
cp -a /lib/x86_64-linux-gnu $1/lib/x86_64-linux-gnu
cp -a /lib64/ld-linux-x86-64.so.2 $1/lib64/ld-linux-x86-64.so.2
