Guidelines
==========

Directories
-----------
After installed, there are several files under the judge directory.

.. code::
  
  judge/
    *.py (Python modules)
    StdChal.py (Standard Challenge module)
    src/
      *.cpp (Core C++ modules)
    inc/
      *.h (Core C++ headers)
    docs/
      *.* (Docs)
    lib/
      libpyext.so (Core built shared library)
    container/
      standard/
        *.* (Standard Container files)
        

Design
------

- ``Python modules`` Interact with the frontend web server.
- ``Standard Challenge module`` Handle standard challenge requests (General compile, Diff judge). It owns the files under "container/standard".
- ``Core modules`` Sandbox core modules. Run tasks in sandboxes, report statistics of tasks.


Different challenge modules will own different container directories. They have to setup their container and use Core modules' API to create tasks to judge the challenges.

For example, for each challenge, the ``Standard Challenge module`` will create two isolated directories under ``container/standard/home``. One is for compiling the code, the other is for judging the program.

``Core modules' API`` enables the challenge modules to run tasks with different UID/GID and namespaces, which guarantees that different tasks are isolated.

Therefore, the ``Standard Challenge module`` can run many compiling tasks and judging tasks concurrently safely. It's job is to make sure that the tasks can't pollute sharing files or touch answer files in the container.
