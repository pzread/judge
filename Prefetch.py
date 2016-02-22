#!/usr/bin/python3
'''Prefetch script.'''

import sys
import os


def main():
    '''Main function.'''

    for filepath in sys.argv[1:]:
        infile_fd = os.open(filepath, os.O_RDONLY)
        infile_size = os.fstat(infile_fd).st_size
        for i in range(0, infile_size, 65536):
            os.lseek(infile_fd, i, os.SEEK_SET)
            os.read(infile_fd, 65536)
        os.close(infile_fd)

    print('1')


if __name__ == '__main__':
    main()
