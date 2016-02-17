#!/usr/bin/python3

import sys
import os

infile_fd = os.open(sys.argv[1], os.O_RDONLY)
infile_size = os.fstat(infile_fd).st_size
for i in range(0, infile_size, 16384):
    os.lseek(infile_fd, i, os.SEEK_SET)
    os.read(infile_fd, 1)
os.close(infile_fd)
print('1')
