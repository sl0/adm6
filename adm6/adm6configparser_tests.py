#!/usr/bin/env python
#encoding:utf8
#
# file:    hostnet6_tests.py
# author: sl0
# date:   2013-03-03
#

import unittest
#from ipaddr import IPv6Network
#from hostnet6 import HostNet6
from adm6configparser import Adm6ConfigParser

class Adm6cConfigParser_test(unittest.TestCase):
    '''some tests for class adm6configparser'''

    def test_01_read_config(self):
        """
        read the config file
        """
        cfg = Adm6ConfigParser()
        print type(cfg)
        print cfg
        print dir(cfg)

if __name__ == "__main__":
        unittest.main()
