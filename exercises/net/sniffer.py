"""
This file contains interface for basic sniffer which support man in the
middle hooks for manipulating web requests.
"""

import abc

from base import platform
from base import command_line
from exercises.net import proxy
from exercises.net import network

import copy
from os import path
import threading
import tempfile
import time
import gzip
import re
import logging
import socket
import select

import Cryptodome
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from OpenSSL import crypto

log = logging.getLogger(__name__)
log.setLevel('DEBUG')
logging.basicConfig()

_author_ = "anton.ohontsev@gmail.com"


class InterfaceSniffer(abc.ABC):
    def start_sniffing(self):
        """"""

    def stop_sniffing(self):
        """"""

    @property
    @abc.abstractmethod
    def is_sniffing_active(self):
        """"""

    @property
    @abc.abstractmethod
    def traffic(self):
        """"""

    def clear_traffic_storage(self):
        """"""

    @property
    @abc.abstractmethod
    def rules(self):
        """"""

    def clear_rules(self):
        """"""

    def add_request_rule(self, match_pattern, request):
        """"""

    def add_response_rule(self, match_pattern):
        """"""

    def remove_request_rule(self, match_pattern, request):
        """"""

    def remove_response_rule(self, match_pattern):
        """"""


class Request(object):
    def __init__(self, result_code=None):
        self.result_code = result_code


class Response(object):
    def __init__(self, result_code=None):
        self.result_code = result_code


VERSION = 'Python Proxy'
HTTPVER = 'HTTP/1.1'


class ConnectionHandler:
    def __init__(self, connection, address, timeout):
        self.client = connection
        self.client_buffer = b''
        self._buffer_length = 8192
        self._http_version = b'HTTP/1.1'
        self._proxy_agent = b'movax01h proxy'

        self.target = None
        self.timeout = timeout
        self.method, self.path, self.protocol = self.get_base_header()
        if self.method == b'CONNECT':
            self.method_CONNECT()
        elif self.method in (b'OPTIONS', b'GET', b'HEAD', b'POST', b'PUT',
                             b'DELETE', b'TRACE'):
            self.method_others()
        self.client.close()
        if self.target:
            self.target.close()

    def get_base_header(self):
        while 1:
            self.client_buffer += self.client.recv(self._buffer_length)
            end = self.client_buffer.find(b'\n')
            if end != -1:
                break
        log.debug('%s' % self.client_buffer[:end])
        data = (self.client_buffer[:end + 1]).split()
        self.client_buffer = self.client_buffer[end + 1:]
        return data

    def method_CONNECT(self):
        self._connect_target(self.path)
        data = self._http_version + b' 200 Connection established\n' + b'Proxy-agent: %s\n\n' % self._proxy_agent
        self.client.send(data)
        self.client_buffer = b''
        self._read_write()

    def method_others(self):
        self.path = self.path[7:]
        i = self.path.find(b'/')
        host = self.path[:i]
        path = self.path[i:]
        self._connect_target(host)
        data = b'%s %s %s\n' % (self.method, path,
                                self.protocol) + self.client_buffer
        self.target.send(data)
        self.client_buffer = b''
        self._read_write()

    def _connect_target(self, host):
        i = host.find(b':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = 80
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family)
        self.target.connect(address)

    def _read_write(self):
        time_out_max = self.timeout / 3
        socs = [self.client, self.target]
        count = 0
        while 1:
            count += 1
            (recv, _, error) = select.select(socs, [], socs, 3)
            if error:
                break
            if recv:
                for in_ in recv:
                    data = in_.recv(self._buffer_length)
                    if in_ is self.client:
                        out = self.target
                    else:
                        out = self.client
                    if data:
                        out.send(data)
                        count = 0
            if count == time_out_max:
                break


class _GenericSniffer(InterfaceSniffer):
    def __init__(self, port=None):
        self._cmd = command_line.CommandLine()
        self._proxy = proxy.Proxy()
        self._server_host = '127.0.0.1'
        self._server_port = port or network.Network().get_free_port()
        self._cert_name = 'SnifferCertificate'
        self._is_sinffing_active = False
        self._traffic = []
        self._rules = []

        log.debug('Sniffer for port {} is initialized.'.format(
            self._server_port))

    def __enter__(self):
        self.start_sniffing()
        return self

    def __exit__(self, *args, **kwargs):
        self.stop_sniffing()
        self._proxy.switch_off()

    def _generate_pem_content(self):
        """
        Generates certificate and saves it to file.

        Arguments:
            - None

        Returns:
            - string with full path to certificate.
        """

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        log.debug('Public key is generated.')

        cert = crypto.X509()
        cert.get_subject().C = "RU"
        cert.get_subject().CN = self._cert_name
        cert.get_subject().OU = self._cert_name
        cert.get_subject().L = self._cert_name
        cert.get_subject().O = self._cert_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        log.debug('Certificate is created.')

        pem_content = crypto.dump_certificate(crypto.FILETYPE_PEM, cert) + \
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

        # File should have ending "-ca.pem" this is magic from mitmproxy.
        cert_full_path = path.join(tempfile.gettempdir(),
                                   '{}-ca.pem'.format(self._cert_name))

        with open(cert_full_path, 'wb') as cert_file:
            cert_file.write(pem_content)

        log.debug('Pem file "%s" is created.' % cert_full_path)

        return cert_full_path

    def _generate_pem_content_new(self):
        k = RSA.generate(2048)
        k.exportKey()

        log.debug('Public key is generated.')

        cert = crypto.X509()
        cert.get_subject().C = "RU"
        cert.get_subject().CN = self._cert_name
        cert.get_subject().OU = self._cert_name
        cert.get_subject().L = self._cert_name
        cert.get_subject().O = self._cert_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        log.debug('Certificate is created.')

        pem_content = crypto.dump_certificate(crypto.FILETYPE_PEM, cert) + \
                      crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

        # File should have ending "-ca.pem" this is magic from mitmproxy.
        cert_full_path = path.join(tempfile.gettempdir(),
                                   '{}-ca-new.pem'.format(self._cert_name))

        with open(cert_full_path, 'wb') as cert_file:
            cert_file.write(pem_content)

        log.debug('Pem file "%s" is created.' % cert_full_path)

        return cert_full_path

    def _generate_and_import_certificate(self):
        raise NotImplementedError("Need implement.")

    def start_sniffing(self):
        if self._is_sinffing_active:
            return

        self._proxy.set_proxy('{}:{}'.format(self._server_host,
                                             self._server_port))
        self._proxy.switch_on()

        # self._generate_and_import_certificate()
        # proxy.CONF_BASENAME = self._cert_name
        # options = Options(
        #     listen_port=self._proxy_port,
        #     cadir=cert_path,
        #     ssl_insecure=True)
        # config = ProxyConfig(options)
        # server = ProxyServer(config)

        log.debug('Proxy server is initialized.')

        ipv6 = False
        timeout = 60

        soc = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

        soc.bind((self._server_host, self._server_port))

        log.debug("Serving on {}:{}.".format(self._server_host,
                                             self._server_port))
        soc.listen(0)
        while True:
            threading.Thread(
                    target=ConnectionHandler,
                    args=(soc.accept() + (timeout, ))).start()
        #soc.close()

        # self._proxy = _Proxy(options, server, self._mock_injector,
        #                      self._mock_recorder, self._override_headers)

        self._is_sinffing_active = True
        # sniffer = threading.Thread(target=self._proxy.run)
        # sniffer.daemon = True
        # sniffer.start()

        log.debug('Sniffing is started.')

    def stop_sniffing(self):
        if not self._is_sinffing_active:
            return

        self._proxy.switch_off()
        self._is_sinffing_active = False

        log.debug('Sniffing is stopped.')

    def is_sniffing_active(self):
        return self._is_sinffing_active

    @property
    def traffic(self):
        return self._traffic

    def clear_traffic_storage(self):
        self._traffic = []

    @property
    def rules(self):
        return self._rules

    def clear_rules(self):
        self._rules = []

    def add_request_rule(self, match_pattern, request):
        """"""

    def add_response_rule(self, match_pattern):
        """"""

    def remove_request_rule(self, match_pattern, request):
        """"""

    def remove_response_rule(self, match_pattern):
        """"""


class _SnifferWin(_GenericSniffer):
    def _generate_and_import_certificate(self):
        cert_full_path = self._generate_pem_content()

        cmd = self._cmd
        result = cmd.execute('certutil -store -enterprise root')

        match = re.search(r'L=%s' % self._cert_name, result)
        if match:
            cert_hash = re.findall(
                r'L=%s[\s\S]+?\(sha1\): ([ \w\d]+)' % self._cert_name,
                result)[0].replace(' ', '')

            cmd.execute('certutil -delstore -enterprise root %s' % cert_hash)
        cmd.execute('certutil -addstore -enterprise root %s' % cert_full_path)

        return path.dirname(cert_full_path)


class _SnifferMac(_GenericSniffer):
    def _generate_and_import_certificate(self):
        cert_full_path = self._generate_pem_content()

        cmd = self._cmd
        keychain = '~/Library/Keychains/login.keychain'
        result = cmd.execute('security find-certificate -a -Z %s' % keychain)

        match = re.search(r'alis"<blob>="%s"' % self._cert_name, result)
        if match:
            cert_hash = re.findall(
                r'[\s\S]*SHA-1 hash: ([\w\d]+)[\s\S]+"alis"<blob>="%s"' %
                self._cert_name, result)[0]
            cmd.execute(
                'sudo security delete-certificate'
                ' -Z %s -t %s >/dev/null 2>&1 || true' % (cert_hash, keychain))

        cmd.execute('sudo security add-trusted-cert -d -r trustRoot -k %s %s' %
                    (keychain, cert_full_path))

        return path.dirname(cert_full_path)


class _SnifferLinux(_GenericSniffer):
    def _generate_and_import_certificate(self):
        cert_full_path = self._generate_pem_content()

        cmd = self._cmd
        cert_new_path = \
            '/usr/local/share/ca-certificates/%s.crt' % self._cert_name
        db_path = 'sql:$HOME/.pki/nssdb'

        if path.isfile(cert_new_path):
            cmd.remove_file_or_folder(cert_new_path, as_admin=True)

        cmd.copy_file_or_folder(cert_full_path, cert_new_path, as_admin=True)
        cmd.execute('sudo certutil -d %s -D -n "%s" '
                    '>/dev/null 2>&1 || true' % (db_path, self._cert_name))
        cmd.execute('sudo certutil -d %s -A -t "C,," -n  '
                    '"%s" -i %s' % (db_path, self._cert_name, cert_full_path))
        cmd.execute('sudo update-ca-certificates')

        return path.dirname(cert_full_path)


if platform.is_(platform.OS_WIN):
    Sniffer = _SnifferWin
elif platform.is_(platform.OS_MAC):
    Sniffer = _SnifferMac
elif platform.is_(platform.OS_LINUX):
    Sniffer = _SnifferLinux
else:
    raise NotImplementedError(
        "Sorry: no implementation for your platform ('{}') available".format(
            platform.get_current_platform()))
