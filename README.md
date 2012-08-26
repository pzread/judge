judge
=====

Compile<br>
-------
g++ -O2 --static judge.cpp -lpsapi -o judge.exe<br/>
g++ -O2 --static --shared judge-dll.cpp -o judge-dll.dll<br/>
Run<br>
---
judge.exe，judge-dll.dll，inittool要放在同目录下。<br/>
<strong>初次运行前或编译judge-dll.dll後，要先用管理员权限运行inittool(依照系统选择32 or 64)。</strong><br/>
judge name.exe time(ms) mem(KB) inputfile ansfile