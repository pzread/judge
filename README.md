judge
=====

g++ -O2 --static judge.cpp -lpsapi -o judge.exe
g++ -O2 --static --shared judge-dll.cpp -o judge-dll.dll

name.exe time(ms) mem(KB) inputfile ansfile
