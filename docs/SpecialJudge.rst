Special Judge
=============

I/O Redirect
------------

.. code:: python

   {
       "comp_type": ${COMP_TYPE},
       "check_type": "iospec",
       "timelimit": ${TIMELIMIT},
       "memlimit": ${MEMLIMIT},
       "metadata": {
           "data": [${TESTDATA_ID},...]
           "redir_test": {
               "testin": -1|${TARGET_FD},
               "testout": -1|${TARGET_FD},
               "pipein": -1|${TARGET_FD},
               "pipeout": -1|${TARGET_FD},
           },
           "redir_judge": {
               "testin": -1|${TARGET_FD},
               "ansin": -1|${TARGET_FD},
               "pipein": -1|${TARGET_FD},
               "pipeout": -1|${TARGET_FD},
           },
       },
   }


``${TESTDATA_ID}`` are IDs of testdata used in the test. The judge will access testdata by opening ``${PRODIR}/res/testdata/data${TESTDATA_ID}.in`` and ``${PRODIR}/res/testdata/data${TESTDATA_ID}.out``.

The test program needs to pass all testdata to get accepted. The ``runtime`` is the overall ``user time`` of all runs. The ``peakmem`` is the highest memory usage of all runs.
