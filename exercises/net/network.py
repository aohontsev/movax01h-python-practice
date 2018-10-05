"""
This file contains utils for manipulating with system proxy settings.
"""

import abc
import contextlib
import logging
import os
import re
import socket
import tempfile
from os import path

from base import command_line
from base import platform

__author__ = "anton.ohontsev@gmail.com"

log = logging.getLogger(__name__)
log.setLevel('DEBUG')
logging.basicConfig()


class NetworkHelperException(Exception):
    pass


class InterfaceNetwork(abc.ABC):
    def hosts_path(self):
        """Return path of hosts file."""

    def block_hosts(self, *hosts):
        """Add host to hosts file with redirection to 10.255.255.1 and
        creates backup file.
        """

    def redirect_hosts(self, hosts):
        """Add host to hosts file with redirection to target IP and
        creates backup file.

        Arguments:
            - hosts: dict, e.g.
                {"192.168.1.77": ("somehost1.com", "somehost2.com"),
                 "192.168.1.78": ("somehost3.com", "somehost4.com")}

        Returns:
            - None
        """

    def restore_hosts(self):
        """Recovery hosts file from backup file."""

    def get_free_port(self):
        """Get free system port."""

    def check_port_free(self, port):
        """Check whether port is free.

        Arguments:
            - port: integer, port number.

        Returns:
            - tuple, (pid, process_name) if port is busy or (None, None) if
              port is free.
        """


class _GenericNetwork(InterfaceNetwork):
    def __init__(self):
        self._cmd = command_line.CommandLine()
        self._hosts_dir = None
        self._hosts_template = ('#-----BEGIN YANDEX CLIPPY TEST DATA-----\n'
                                '%s\n'
                                '#-----END YANDEX CLIPPY TEST DATA-----')
        self._hosts_pattern = re.compile(
            self._hosts_template % r'(.*)', flags=re.DOTALL)

    @property
    def hosts_path(self):
        return path.join(self._hosts_dir, 'hosts')

    def block_hosts(self, *hosts):
        log.debug('Blocking hosts: {}'.format(hosts))
        self.redirect_hosts({'10.255.255.1': hosts})

    def _modify_hosts_file(self, func):
        """ Modifies hosts file as dictated by function.
        This method copies hosts file to a staging location, applies function
        to it, and copies it back to where it came from.

        Arguments:
            - function: Callable that gets full path to staged hosts file, and
            performs some actions on its content.

        Returns:
            - None
        """

        tmp_hosts_path = path.join(tempfile.gettempdir(), 'hosts.tmp')
        self._cmd.copy_file_or_folder(
            self.hosts_path, tmp_hosts_path, as_admin=False)

        func(tmp_hosts_path)

        self._cmd.copy_file_or_folder(
            tmp_hosts_path, self.hosts_path, as_admin=True)
        self._cmd.remove_file_or_folder(
            tmp_hosts_path, forced=True, as_admin=True)

    def _add_redirected_hosts(self, hosts):
        # TODO: add description
        def func(file_path):
            with open(file_path, 'r') as hosts_file:
                hosts_file_content = hosts_file.read()

            blocked_hosts = self._hosts_pattern.findall(hosts_file_content)

            if blocked_hosts:
                # Parsing already blocked hosts back to
                # {'ip': ('host1', 'host2')} structure.
                blocked_hosts = {
                    host.split(' ', 1)[0]: set(host.split(' ', 1)[1].split())
                    for host in blocked_hosts[0].split('\n')
                }

                for ip, hostnames in hosts.items():
                    # Adding new hosts to already blocked only if they are
                    # not already there.
                    blocked_hosts.setdefault(ip, set()).update(hostnames)

            else:
                blocked_hosts = hosts
                # Adding empty section to the end of host file content.
                hosts_file_content += '\n' + self._hosts_template % ''

            data_block = '\n'.join('%s %s'.format(k, ' '.join(v))
                                   for k, v in blocked_hosts.items())

            # Preparing new content for hosts file.
            hosts_file_content = self._hosts_pattern.sub(
                self._hosts_template % data_block, hosts_file_content)

            with open(file_path, 'w') as hosts_file:
                hosts_file.write(hosts_file_content)

        return func

    def redirect_hosts(self, hosts):
        self._modify_hosts_file(self._add_redirected_hosts(hosts))

    def restore_hosts(self):
        log.debug('Unblocking all hosts.')

        def remove_test_hosts(file_path):
            with open(file_path, 'r') as hosts_file:
                hosts_file_content = hosts_file.read()

            # Removing test data content content from hosts file.
            hosts_file_content = self._hosts_pattern.sub(
                '', hosts_file_content).rstrip('\n')

            with open(file_path, 'w') as hosts_file:
                hosts_file.write(hosts_file_content)

        self._modify_hosts_file(remove_test_hosts)

    def get_free_port(self):
        free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with contextlib.closing(free_socket):
            free_socket.bind(('0.0.0.0', 0))
            port = free_socket.getsockname()[1]
            log.info('Select port {}.'.format(port))
            return port


class _NetworkWin(_GenericNetwork):
    def __init__(self):
        super().__init__()
        _hosts_dir = path.join(os.environ['WINDIR'], 'System32\drivers\etc')

    def check_port_free(self, port):
        result = self._cmd.execute('netstat -baon').split('\r\n')
        amount = len(result)
        port = ':%s' % port
        for idx, elem in enumerate(result):
            if port in elem:
                pid = elem.split()[-1]
                if idx + 2 < amount and result[idx +
                                               2].split()[-1].startswith('['):
                    process_name = result[idx + 2].split()[-1]
                else:
                    process_name = result[idx + 1].split()[-1]
                process_name = process_name.strip('[]')
                return pid, process_name

        return None, None


class _NetworkMac(_GenericNetwork):
    def __init__(self):
        super().__init__()
        self._hosts_dir = '/etc'

    def restore_hosts(self):
        super().restore_hosts()
        # Kill mDNSResponder (it will restart) to clear DNS cache.
        self._cmd.execute('sudo killall mDNSResponder || true')

    def check_port_free(self, port):
        result = self._cmd.execute(
            ('sudo lsof -Pn| awk \'{ if ($9 ~ /:{port}/) print $2, $1}\''
             ).format(port=port))
        if not result:
            return None, None

        result = result.split('\n')[0]
        return result.split()


class _NetworkLinux(_GenericNetwork):
    def __init__(self):
        super().__init__()
        self._hosts_dir = '/etc'

    def check_port_free(self, port):
        result = self._cmd.execute(
            ('sudo netstat -pn| awk \'{ if ($4 ~ /:{port}/) print $6}\''
             ).format(port=port))
        if not result:
            return None, None

        result = result.split('\n')[0]
        return result.split('/')


if platform.is_(platform.OS_WIN):
    Network = _NetworkWin
elif platform.is_(platform.OS_MAC):
    Network = _NetworkMac
elif platform.is_(platform.OS_LINUX):
    Network = _NetworkLinux
else:
    raise NotImplementedError(
        "Sorry: no implementation for your platform ('{}') available".format(
            platform.get_current_platform()))
