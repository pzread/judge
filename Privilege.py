import os
import pwd
import contextlib


judge_uid = None
judge_gid = None
nobody_uid = None
nobody_gid = None


def init():
    global judge_uid
    global judge_gid
    global nobody_uid
    global nobody_gid

    judge_pwd = pwd.getpwnam('judge')
    nobody_pwd = pwd.getpwnam('nobody')
    judge_uid = judge_pwd[2]
    judge_gid = judge_pwd[3]
    nobody_uid = nobody_pwd[2]
    nobody_gid = nobody_pwd[3]

    os.setgroups([])
    drop()


def drop():
    os.setegid(0)
    os.seteuid(0)
    os.setegid(nobody_gid)
    os.seteuid(nobody_uid)


@contextlib.contextmanager
def fileaccess():
    os.setegid(0)
    os.seteuid(0)
    os.setegid(judge_gid)
    os.seteuid(judge_uid)
    try:
        yield
    finally:
        drop()


@contextlib.contextmanager
def fullaccess():
    os.setegid(0)
    os.seteuid(0)
    try:
        yield
    finally:
        drop()
