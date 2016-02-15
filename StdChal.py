import os
import shutil
import PyExt
import Config


class StdChal:
    last_compile_uid = Config.CONTAINER_STANDARD_UID_BASE
    last_judge_uid = Config.CONTAINER_RESTRICT_UID_BASE

    def init():
        try:
            shutil.rmtree('container/standard/home')
        except FileNotFoundError:
            pass
        os.mkdir('container/standard/home', mode=0o711)

    def __init__(self, chal_id, code_path):
        self.chal_id = chal_id
        StdChal.last_compile_uid += 1
        self.compile_uid = StdChal.last_compile_uid
        self.compile_gid = Config.CONTAINER_STANDARD_GID
