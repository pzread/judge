'''Privilege module.

Control judge privileges.

Attributes:
    JUDGE_UID (int): UID of judge account.
    JUDGE_GID (int): GID of judge account.
    NOBODY_YID (int): UID of nobody account.
    NOBODY_GID (int): GID of nobody account.

'''

import os
import pwd
import contextlib


JUDGE_UID = None
JUDGE_GID = None
NOBODY_YID = None
NOBODY_GID = None


def init():
    '''Initialize the module.'''

    global JUDGE_UID
    global JUDGE_GID
    global NOBODY_YID
    global NOBODY_GID

    judge_pwd = pwd.getpwnam('judge')
    nobody_pwd = pwd.getpwnam('nobody')
    JUDGE_UID = judge_pwd[2]
    JUDGE_GID = judge_pwd[3]
    NOBODY_YID = nobody_pwd[2]
    NOBODY_GID = nobody_pwd[3]

    os.setgroups([])
    drop(NOBODY_YID, NOBODY_GID)


def drop(uid, gid):
    '''Drop privilege.

    Args:
        uid (int): UID to set.
        gid (int): GID to set.

    Returns:
        None

    '''

    os.setegid(0)
    os.seteuid(0)
    os.setegid(gid)
    os.seteuid(uid)


@contextlib.contextmanager
def fileaccess():
    '''File access contextmanager.'''

    old_euid = os.geteuid()
    old_egid = os.getegid()
    os.setegid(0)
    os.seteuid(0)
    os.setegid(JUDGE_GID)
    os.seteuid(JUDGE_UID)
    try:
        yield
    finally:
        drop(old_euid, old_egid)


@contextlib.contextmanager
def fullaccess():
    '''Full access contextmanager.'''

    old_euid = os.geteuid()
    old_egid = os.getegid()
    os.setegid(0)
    os.seteuid(0)
    try:
        yield
    finally:
        drop(old_euid, old_egid)
