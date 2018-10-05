"""
This file contains utils for manipulating with system proxy settings.
"""

import abc
from base import command_line
from base import platform

if platform.is_(platform.OS_WIN):
    import ctypes
    from ctypes import wintypes

__author__ = "anton.ohontsev@gmail.com"


class InterfaceProxy(abc.ABC):
    def switch_on(self):
        """Switch proxy on."""

    def switch_off(self):
        """Switch proxy off."""

    def set_proxy(self, proxy, exceptions='', bypass_local=True):
        """Setting system proxy.

        Arguments:
            - proxy: string, proxy ip and port e.g. '127.0.0.1:1708'.
            - exception: string, proxy exceptions separated by semicolons.
            - bypass_local: bool, flag to bypass proxy server for
            local addresses.

        Returns:
            - None
        """

    def enable_pac(self, pac_url):
        """Enable PAC.

        A proxy auto-config (PAC) file defines how web browsers and other user
        agents can automatically choose the appropriate proxy server (access
        method) for fetching a given URL.

        Arguments:
            - pac_url: string, pac url.

        Returns:
            - None
        """

    def disable_pac(self):
        """Disable PAC."""


class _GenericProxy(InterfaceProxy):
    def __init__(self):
        self._is_started = False
        self._cmd = command_line.CommandLine()


class _ProxyWin(_GenericProxy):
    """Proxy for windows os. Release by using win module WinInet."""

    def __init__(self):
        super().__init__()

        LPWSTR = wintypes.POINTER(wintypes.WCHAR)
        HINTERNET = wintypes.LPVOID

        # INTERNET_PER_CONN_OPTION available types
        self.INTERNET_PER_CONN_FLAGS = 1  # Setting current connection type
        self.INTERNET_PER_CONN_PROXY_SERVER = 2  # Setting proxy server url and port
        self.INTERNET_PER_CONN_PROXY_BYPASS = 3  # Setting proxy override
        self.INTERNET_PER_CONN_AUTOCONFIG_URL = 4  # Setting auto config url
        self.INTERNET_PER_CONN_AUTODISCOVERY_FLAGS = 5  # Setting auto discovery type

        # InternetSetOption available commands
        self.INTERNET_OPTION_REFRESH = 37
        self.INTERNET_OPTION_SETTINGS_CHANGED = 39
        self.INTERNET_OPTION_PER_CONNECTION_OPTION = 75

        # Available connection types
        self.PROXY_TYPE_DIRECT = 1
        self.PROXY_TYPE_PROXY = 2
        self.PROXY_TYPE_AUTO_PROXY_URL = 4
        self.PROXY_TYPE_AUTO_DETECT = 8

        class INTERNET_PER_CONN_OPTION(wintypes.Structure):
            """Internet connection option type for WinInet module."""

            class Value(wintypes.Union):
                _fields_ = [
                    ('dwOption', wintypes.DWORD),
                    ('pszValue', wintypes.LPWSTR),
                    ('dwValue', wintypes.DWORD),
                    ('ftValue', wintypes.FILETIME),
                ]

            _fields_ = [
                ('dwOption', wintypes.DWORD),
                ('Value', Value),
            ]

        class INTERNET_PER_CONN_OPTION_LIST(wintypes.Structure):
            """Internet connection option list type for WinInet module."""
            _fields_ = [
                ('dwSize', wintypes.DWORD),
                ('pszConnection', LPWSTR),
                ('dwOptionCount', wintypes.DWORD),
                ('dwOptionError', wintypes.DWORD),
                ('pOptions', wintypes.POINTER(INTERNET_PER_CONN_OPTION)),
            ]

        self.INTERNET_PER_CONN_OPTION = INTERNET_PER_CONN_OPTION
        self.INTERNET_PER_CONN_OPTION_LIST = INTERNET_PER_CONN_OPTION_LIST

        self.InternetSetOption = ctypes.windll.wininet.InternetSetOptionW
        self.InternetSetOption.argtypes = [
            HINTERNET, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD
        ]
        self.InternetSetOption.restype = wintypes.BOOL

    def _internet_set_option(self, command, options=None):
        if options:
            size = wintypes.c_ulong(wintypes.sizeof(options))
            options = wintypes.byref(options)
        else:
            size = 0
        assert self.InternetSetOption(None, command, options, size)

    def _get_internet_per_conn_option_list(self, option):
        option_list = self.INTERNET_PER_CONN_OPTION_LIST()
        option_list.dwSize = self.wintypes.sizeof(
            self.INTERNET_PER_CONN_OPTION_LIST)
        option_list.pszConnection = None
        option_list.dwOptionCount = len(option)
        option_list.dwOptionError = 0
        option_list.pOptions = option
        return option_list

    def _get_internet_per_conn_option(self, settings):
        option = (self.INTERNET_PER_CONN_OPTION * len(settings))()
        for i, setting in enumerate(settings):
            option[i].dwOption = setting['option']
            value = setting['value']
            if isinstance(value, int):
                option[i].Value.dwValue = value
            elif isinstance(value, str):
                option[i].Value.pszValue = value
            else:
                raise TypeError
        return option

    def _refresh_settings(self):
        self._internet_set_option(self.INTERNET_OPTION_SETTINGS_CHANGED)
        self._internet_set_option(self.INTERNET_OPTION_REFRESH)

    def switch_on(self):
        if not self._is_started:
            settings = [{
                'option': self.INTERNET_PER_CONN_FLAGS,
                'value': self.PROXY_TYPE_PROXY
            }]
            option = self._get_internet_per_conn_option(settings)
            options = self._get_internet_per_conn_option_list(option)
            self._internet_set_option(
                self.INTERNET_OPTION_PER_CONNECTION_OPTION, options)
            self._refresh_settings()
            self._is_started = True

    def switch_off(self):
        if self._is_started:
            settings = [{
                'option': self.INTERNET_PER_CONN_FLAGS,
                'value': self.PROXY_TYPE_DIRECT
            }]
            option = self._get_internet_per_conn_option(settings)
            options = self._get_internet_per_conn_option_list(option)
            self._internet_set_option(
                self.INTERNET_OPTION_PER_CONNECTION_OPTION, options)
            self._refresh_settings()
            self._is_started = False

    def set_proxy(self, proxy, exceptions='', bypass_local=True):
        # We can't use here <local> as designed because of "502 Bad Gateway"
        # issue that will appeared in selenium.webdriver.
        exceptions += ';localhost;127.0.0.1' * bypass_local

        settings = [{
            'option': self.INTERNET_PER_CONN_PROXY_SERVER,
            'value': proxy
        }, {
            'option': self.INTERNET_PER_CONN_PROXY_BYPASS,
            'value': exceptions
        }]
        option = self._get_internet_per_conn_option(settings)
        options = self._get_internet_per_conn_option_list(option)
        self._internet_set_option(self.INTERNET_OPTION_PER_CONNECTION_OPTION,
                                  options)
        self._refresh_settings()

    def enable_pac(self, pac_url):
        settings = [{
            'option': self.INTERNET_PER_CONN_FLAGS,
            'value': self.PROXY_TYPE_AUTO_PROXY_URL
        }, {
            'option': self.INTERNET_PER_CONN_AUTOCONFIG_URL,
            'value': pac_url
        }]
        option = self._get_internet_per_conn_option(settings)
        options = self._get_internet_per_conn_option_list(option)
        self._internet_set_option(self.INTERNET_OPTION_PER_CONNECTION_OPTION,
                                  options)
        self._refresh_settings()

    def disable_pac(self):
        settings = [{
            'option': self.INTERNET_PER_CONN_FLAGS,
            'value': self.PROXY_TYPE_DIRECT
        }]
        option = self._get_internet_per_conn_option(settings)
        options = self._get_internet_per_conn_option_list(option)
        self._internet_set_option(self.INTERNET_OPTION_PER_CONNECTION_OPTION,
                                  options)
        self._refresh_settings()


class _ProxyMac(_GenericProxy):
    def _get_active_network_service(self):
        """Get current active network service such as (e.g. 'Wi-Fi' or 'Ethernet').

        First we need get current network interface, a BSD name of network interface (e.g 'en0').
        Then 'networksetup' command help us to get friendly name by BSD name.
        """
        bsd_name = self._cmd.execute(
            "route -n get 0.0.0.0 2>/dev/null | awk '/interface: / {print $2}'"
        )
        bsd_name = bsd_name.rstrip('\n')

        return self._cmd.execute(
            "networksetup -listallhardwareports | grep -B1 '{bsd_name}' | awk -F ': ' '/Hardware Port/ {{print $2}}'"
            .format(bsd_name=bsd_name)).rstrip('\n')

    def _execute_proxy_command(self, command, *args):
        cmd = 'sudo networksetup -{command} "{service}" {arguments}'.format(
            command=command,
            service=self._get_active_network_service(),
            arguments=' '.join(args))
        self._cmd.execute(cmd)

    def switch_on(self):
        if not self._is_started:
            self._execute_proxy_command('setwebproxystate', 'on')
            self._execute_proxy_command('setsecurewebproxystate', 'on')
            self._is_started = True

    def switch_off(self):
        if self._is_started:
            self._execute_proxy_command('setwebproxystate', 'off')
            self._execute_proxy_command('setsecurewebproxystate', 'off')
            self._is_started = False

    def set_proxy(self, proxy, exceptions='', bypass_local=True):
        proxy_ip_port = ' '.join(proxy.split(':'))
        self._execute_proxy_command('setwebproxy', proxy_ip_port)
        self._execute_proxy_command('setsecurewebproxy', proxy_ip_port)

        args = exceptions.split(';') if exceptions else []
        if bypass_local:
            args.append('127.0.0.1')

        self._execute_proxy_command('setproxybypassdomains', *args)

    def enable_pac(self, pac_url):
        self._execute_proxy_command('setautoproxyurl', pac_url)
        self._execute_proxy_command('setautoproxystate', 'on')

    def disable_pac(self):
        self._execute_proxy_command('setautoproxystate', 'off')


class _ProxyLinux(_GenericProxy):
    def _execute_proxy_command(self, command, *args):
        cmd = 'sudo gsettings set {command} {arguments}'.format(
            command=command, arguments=' '.join(args))
        self._cmd.execute(cmd)

    def switch_on(self):
        if not self._is_started:
            self._execute_proxy_command('org.gnome.system.proxy', 'mode',
                                        '\'manual\'')
            self._is_started = True

    def switch_off(self):
        if self._is_started:
            self._execute_proxy_command('org.gnome.system.proxy', 'mode',
                                        '\'none\'')
            self._is_started = False

    def set_proxy(self, proxy, exceptions='', bypass_local=True):
        proxy_ip, port = proxy.split(':')
        for scheme in 'http', 'https', 'ftp':
            self._execute_proxy_command(
                'org.gnome.system.proxy.{} host'.format(scheme),
                '\'{}\''.format(proxy_ip))
            self._execute_proxy_command(
                'org.gnome.system.proxy.{} port'.format(scheme), port)

        args = exceptions.split(';') if exceptions else []
        if bypass_local:
            args.append('127.0.0.1')

        self._execute_proxy_command('org.gnome.system.proxy', 'ignore-hosts',
                                    '\'{}\''.format(args))

    def enable_pac(self, pac_url):
        self._execute_proxy_command('org.gnome.system.proxy', 'autoconfig-url',
                                    pac_url)
        self._execute_proxy_command('org.gnome.system.proxy', 'mode', "'auto'")

    def disable_pac(self):
        self.switch_off()


if platform.is_(platform.OS_WIN):
    Proxy = _ProxyWin
elif platform.is_(platform.OS_MAC):
    Proxy = _ProxyMac
elif platform.is_(platform.OS_LINUX):
    Proxy = _ProxyLinux
else:
    raise NotImplementedError(
        "Sorry: no implementation for your platform ('{}') available".format(
            platform.get_current_platform()))
