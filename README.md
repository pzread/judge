judge
=====

g++ -O2 --static judge.cpp -lpsapi -o judge.exe

g++ -O2 --static --shared judge-dll.cpp -o judge-dll.dll

第一次執行時先以管理員權限執行inittool(依照系統選擇32 or 64)

judge name.exe time(ms) mem(KB) inputfile ansfile