"""
This file contains utils which provides work with system command line.
"""

import abc
import ctypes
import datetime
import functools
import logging
import os
import shutil
import subprocess
from os import path

from base import platform
from base import waiter

_author_ = "anton.ohontsev@gmail.com"

log = logging.getLogger(__name__)
log.setLevel('DEBUG')
logging.basicConfig()


class InterfaceCommandLine(abc.ABC):
    def execute(self, commands, timeout=0):
        """Execute commands via CLI.

        Arguments:
            - commands_list: list, list of commands.
            E.g. ['cmd', '/c', command]
            - timeout: None - async execution, 0 - wait process finishing,
              int - wait process finishing during specified seconds.

        Return:
            - Result of execution.
        """

    def wait_process_finished(self, process_name, timeout=30):
        """Wait until the process finished."""

    def wait_process_appears(self, process_name, timeout=30):
        """Wait until the process appears."""

    def terminate_process(self, process_name):
        """Terminate process."""

    def set_clipboard(self, text):
        """Set clipboard content to a given text."""

    def get_processes_list(self):
        """Get list of currently running processes."""

    def remove_file_or_folder(self, file_path, forced=True, as_admin=False):
        """Removes file or folder.

        Arguments:
            - file_path: string, path to file or folder.
            - forced: bool, if True "-f" flag will be used.
            - as_admin: bool, if True command will be executed with
            sudo for *nix systems.

        Return:
            - None
        """

    def copy_file_or_folder(self, file_path, dest_file_path, as_admin=False):
        """Copies file.

        Arguments:
            - file_path: string, path to file.
            - dest_file_path: string, destination path, including file name.
            - as_admin: bool, if True command will be executed with
            sudo for *nix systems.

        Return:
            - None
        """

    def make_file_executable(self, file_path):
        """Makes a file executable."""

    def get_process_commandline(self, process_name):
        """Gets list of process commandline info.

        Arguments:
            - process_name: string, process name.

        Returns:
            - list, process commandline.
        """


class _GenericCommandLine(InterfaceCommandLine):
    def execute(self, commands, timeout=0):
        start_time = datetime.datetime.now()
        try:
            log.debug("Executing shell command: '{}'.".format(commands))

            result = ''
            if timeout is None:
                subprocess.Popen(commands, shell=True)
            else:
                co = functools.partial(
                    subprocess.check_output, args=commands, shell=True)
                result = co() if timeout == 0 else co(timeout=timeout)
            log.debug("Executing shell command finished. Executing time: {}.".
                      format(datetime.datetime.now() - start_time))
            return result.decode('ascii')

        except subprocess.CalledProcessError as ex:
            raise RuntimeError(
                ("'{0}' finished with {1} exit code. Message is: {2}. "
                 "Executing time: {3}").format(
                     commands, ex.returncode, ex.output,
                     datetime.datetime.now() - start_time))

    def wait_process_finished(self, process_name, timeout=30):
        return waiter.waiter_poll(
            timeout,
            lambda: not process_name.lower() in self.get_processes_list())

    def wait_process_appears(self, process_name, timeout=30):
        return waiter.waiter_poll(
            timeout, lambda: process_name.lower() in self.get_processes_list())

    def make_file_executable(self, file_path):
        raise NotImplementedError(
            "Sorry: no implementation for your platform ('{}') available".
            format(platform.get_current_platform()))


class _CommandLineWin(_GenericCommandLine):
    def terminate_process(self, process_name):
        self.execute(
            'TASKKILL /F /IM "{}" /T >NUL 2>&1 || exit 0'.format(process_name))

    def set_clipboard(self, text):
        text = text + ' \x00'
        # To be honest I didn't quite get how to allocated smallest
        # sufficient length for multi-byte-char strings. So we allocate
        # (n-bytes + 1) * length + 1, which should be enough for all cases.
        allocated_length = \
            sum(len(c.encode('UTF-8')) + 1 for c in text) + 1
        GMEM_DDESHARE = 0x2000
        ctypes.windll.user32.OpenClipboard(0)
        ctypes.windll.user32.EmptyClipboard()
        hCd = ctypes.windll.kernel32.GlobalAlloc(GMEM_DDESHARE,
                                                 allocated_length)
        pchData = ctypes.windll.kernel32.GlobalLock(hCd)
        # Use wcscpy to copy multi-byte-char strings.
        ctypes.cdll.msvcrt.wcscpy(ctypes.c_wchar_p(pchData), text)
        ctypes.windll.kernel32.GlobalUnlock(hCd)
        # 13 stands for CF_UNICODETEXT, set it as clipboard type.
        ctypes.windll.user32.SetClipboardData(13, hCd)
        ctypes.windll.user32.CloseClipboard()

    def get_processes_list(self):
        processes = self.execute('wmic process get description')
        return [process.lower() for process in processes.split()]

    def remove_file_or_folder(self, file_path, forced=True, as_admin=False):
        if path.isfile(file_path):
            os.remove(file_path)
        else:
            shutil.rmtree(file_path, True)

    def copy_file_or_folder(self, file_path, dest_file_path, as_admin=False):
        if path.isfile(file_path):
            shutil.copyfile(file_path, dest_file_path)
        else:
            shutil.copytree(file_path, dest_file_path)

    def get_process_commandline(self, process_name):
        processes = self.execute(
            'wmic process where description=\'{}\' get commandline'.format(
                process_name))
        return [
            process.strip() for process in processes.splitlines()
            if process.strip() not in ['', 'CommandLine']
        ]


class _CommandLineLinux(_GenericCommandLine):
    def terminate_process(self, process_name):
        return self.execute(
            'killall -9 "{}" -z >/dev/null 2>&1; exit 0'.format(process_name))

    def get_proc_list(self):
        processes = self.execute('ps ax | awk \'{print $5}\' | '
                                 'awk -F "/" \'{print $NF}\'')
        return [process.lower() for process in processes.split()]

    def remove_file_or_folder(self, file_path, forced=True, as_admin=False):
        command = '{sudo}rm -r{force} "{file_path}"'.format(
            sudo='sudo' if as_admin else '',
            force='f' if forced else '',
            file_path=file_path)
        return self.execute(command)

    def copy_file_or_folder(self, file_path, dest_file_path, as_admin=False):
        command = '{sudo}cp -R "{file_path}" "{dest_file_path}"'.format(
            sudo='sudo' if as_admin else '',
            file_path=file_path,
            dest_file_path=dest_file_path)
        return self.execute(command)

    def make_file_executable(self, file_path):
        self.execute('chmod u+x "{}"'.format(file_path))

    def get_process_commandline(self, process_name):
        procs = self.execute("ps -eo args | grep '{}".format(process_name))
        return [
            proc.strip() for proc in procs.splitlines()
            if proc.strip() not in ['']
        ]

    def set_clipboard(self, text):
        self.execute('echo "{}" | xclip -selection clipboard'.format(text))


class _CommandLineMac(_CommandLineLinux):
    def set_clipboard(self, text):
        with os.popen('pbcopy', 'w') as outf:
            outf.write(text)


if platform.is_(platform.OS_WIN):
    CommandLine = _CommandLineWin
elif platform.is_(platform.OS_MAC):
    CommandLine = _CommandLineMac
elif platform.is_(platform.OS_LINUX):
    CommandLine = _CommandLineLinux
else:
    raise NotImplementedError(
        "Sorry: no implementation for your platform ('{}') available".format(
            platform.get_current_platform()))
