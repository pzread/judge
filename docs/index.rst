.. Judge - HypeX documentation master file, created by
   sphinx-quickstart on Tue Feb 23 01:02:44 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Judge - HypeX documentation
=========================================

Judge - HypeX is a judge system which focuses on performance and security.

It requires root permission to run. The host must have the full ``Linux namespaces`` support and the ``memory cgroup``, also the ``access control lists(acl)`` needs to be enabled on the file system.


Requirements
------------

- python3 >= 3.4
- python3-pip
- gcc >= 5
- g++ >= 5
- clang >= 3.6
- cmake >= 2.8
- libcgroup-dev >= 0.41
- acl


Installation
------------

build-container.sh is used to copy files from the host to create the container. Currently, it is designed for ``Ubuntu 15.10 x86_64``. You may need to modify it to fit your host's file system.

.. code::
   
   git clone https://github.com/pzread/judge.git
   cd judge
   pip3 install -r requirements.txt
   mkdir lib
   cd lib
   cmake ..
   make
   cd ..
   ./setup.sh


Usage
-----

.. code::
   
   cd judge
   sudo python3 Server.py
   

.. WARNING::
   
   Before delete the ``container`` directory, always remember to umount the ``udev file systems`` under it.


Run Tests
--------

.. code::

   python3 -m tornado.test.runtests tests.TestAll


Tables of contents
==================

.. toctree::
   :maxdepth: 4

   Guidelines
   Docstrings


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

