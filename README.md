judge
=====

Compile<br>
-------
g++ -O2 --static judge.cpp -lpsapi -o judge.exe<br/>
g++ -O2 --static --shared judge-dll.cpp -o judge-dll.dll<br/>
Run<br>
---
<strong>第一次執行時先以管理員權限執行inittool(依照系統選擇32 or 64)</strong><br/>
judge name.exe time(ms) mem(KB) inputfile ansfile