"""
This file contains unit-tests for sniffer implementation.
"""

import unittest
from urllib import request

from exercises.net import sniffer as sniffer_lib

_author_ = "anton.ohontsev@gmail.com"


class TestSnifferWin(unittest.TestCase):
    def test_start_sniffing(self):
        with sniffer_lib.Sniffer() as sniffer:
            self.assertTrue(sniffer.is_sniffing_active())

    def test_stop_sniffing(self):
        sniffer = sniffer_lib.Sniffer()
        with sniffer:
            self.assertTrue(sniffer.is_sniffing_active())
        self.assertFalse(sniffer.is_sniffing_active())

    def test_catch_request(self):
        with sniffer_lib.Sniffer() as sniffer:
            request.urlopen("http://example.com/foo/bar")
            self.assertIsNotNone(sniffer.traffic, "sniffer caught request")

    def test_generate_pem_file(self):
        sniffer = sniffer_lib.Sniffer()
        pem_file = sniffer._generate_pem_content()
        pem_file_new = sniffer._generate_pem_content_new()
        a = 1

    def test_catch_ipv6_request(self):
        assert True is False
