#!/bin/sh

umask 022

mkdir -p $1/bin
mkdir -p $1/usr/bin
mkdir -p $1/usr/lib
mkdir -p $1/lib
mkdir -p $1/lib64
mkdir -p $1/proc
mkdir -p $1/dev

cp /bin/sh $1/bin/sh
cp /usr/bin/g++ $1/usr/bin/g++
cp -a /usr/bin/clang++ $1/usr/bin/clang++
cp /usr/bin/as $1/usr/bin/as
cp /usr/bin/ld $1/usr/bin/ld
cp /usr/bin/make $1/usr/bin/make
cp /usr/bin/python3.6 $1/usr/bin/python3.6
cp -a /usr/lib/x86_64-linux-gnu $1/usr/lib/x86_64-linux-gnu
cp -a /usr/lib/gcc $1/usr/lib/gcc
cp -a /usr/lib/llvm-6.0 $1/usr/lib/llvm-6.0
cp -a /usr/lib/python3.6 $1/usr/lib/python3.6
cp -a /usr/lib/locale $1/usr/lib/locale
cp -a /usr/include $1/usr/include
cp -a /lib/x86_64-linux-gnu $1/lib/x86_64-linux-gnu
cp -a /lib64/ld-linux-x86-64.so.2 $1/lib64/ld-linux-x86-64.so.2

sudo chown -R judge:judge $1
sudo setfacl -R -m d:g:judge:rwx $1
sudo setfacl -R -m d:u:judge:rwx $1
