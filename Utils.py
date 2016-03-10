'''Utils module.'''


import os
import shutil
import Privilege
from tornado.stack_context import StackContext


class FileUtils:
    '''Utils.'''

    @staticmethod
    def copydir(src, dst):
        '''Copy directory.

        Args:
            src (string): Source path.
            dst (string): Destination path.

        Returns:
            None

        '''

        def _copy_fn(src, dst, follow_symlinks=True):
            '''Copytree helper function.

            Args:
                src (string): Source path.
                dst (string): Destination path.
                follow_symlinks: Follow symbolic link or not.

            Returns:
                None

            '''

            shutil.copy(src, dst, follow_symlinks=False)

        with StackContext(Privilege.fileaccess):
            shutil.copytree(src, dst, symlinks=True, copy_function=_copy_fn)

    @staticmethod
    def setperm(path, uid, gid, umask=0o777):
        '''Set permission of the file or directory.

        Args:
            path (string): File or directory path.
            uid (int): UID of the files and directories.
            gid (int): GID of the files and directories.
            umask (int) optional: Umask of the files and directories.

        Returns:
            None

        '''

        path_set = set([path])
        with StackContext(Privilege.fileaccess):
            for root, dirs, files in os.walk(path, followlinks=False):
                for name in dirs:
                    path_set.add(os.path.abspath(os.path.join(root, name)))
                for name in files:
                    path_set.add(os.path.abspath(os.path.join(root, name)))
        with StackContext(Privilege.fullaccess):
            for path in path_set:
                os.chown(path, uid, gid)
                os.chmod(path, os.stat(path).st_mode & umask)
