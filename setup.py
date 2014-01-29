import os
from distutils.core import setup,Extension

os.environ['CC'] = 'clang'
os.environ['CFLAGS'] = '-Wno-unused-result'

pyext_module = Extension('pyext',
        sources = [
            'src/pyext.c',
            'src/contro.c',
            'src/fog.c',
            'src/snap.c',
            'src/task.c',
            'src/ev.c'
        ],
        include_dirs = ["include"])

setup(name = 'pyext',
        version = '1.0',
        description = 'PyExt package',
        ext_modules = [pyext_module])
