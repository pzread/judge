#!/usr/bin/python3
'''Hash directory script.'''

import sys
import os
import hashlib


def main():
    '''Main function.'''

    pathlist = []
    for root, dirs, files in os.walk(sys.argv[1], followlinks=False):
        for name in dirs:
            pathlist.append(os.path.join(root, name))
        for name in files:
            pathlist.append(os.path.join(root, name))
    
    pathlist.sort()
    md = hashlib.sha256()
    for path in pathlist:
        tmpmd = hashlib.sha256()
        tmpmd.update(path.encode('utf-8'))
        md.update(tmpmd.digest())
        if os.path.isfile(path) and not os.path.islink(path):
            regf = open(path, 'rb')
            tmpmd = hashlib.sha256()
            while True:
                data = regf.read(65536)
                if len(data) <= 0:
                    break
                tmpmd.update(data)
            md.update(tmpmd.digest())
    print(md.hexdigest())


if __name__ == '__main__':
    main()
