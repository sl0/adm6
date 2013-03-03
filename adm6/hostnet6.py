#!/usr/bin/env python
#encoding:utf8
#
# file:    hostnet6.py
# author: sl0
# date:   2013-03-03
#

import unittest
from ipaddr import IPv6Network

#def nice_print(title,mytext):
#    """nice printout of a config line, only to impress the user
#    used linelength: 70 characters"""
#    rest_len = 78 - len(title) - len(mytext)
#    print title + " " + mytext + " "*rest_len + "#"


class HostNet6(IPv6Network):
    """Instance is content of hostnet6-file
    as a sorted list of lists of: (name,address!!!es!!!)
    every line in file may be like:
    NAME   ADDRESS # COMMENT
                or
    # COMMENT
    """
    def __init__(self,file="reference-hostnet"):
        """read file into self.entries"""
        self.entries = []
        self.__read_file(file)

    def __mycmp__(self,l1,l2):
        """zum sortieren der Liste von [[name,adresse]]"""
        (n1,a1) = l1
        (n2,a2) = l2        
        return cmp(n1, n2)

    def __read_file(self,filename):
        """reads file using filename and creates self.entries
        for every line read successfully
        """
        try:
            file1 = open(filename,'r')
        except:
            msg = "No readable file: %s" % filename
            raise ValueError, msg
        linenr = 0
        for zeile in file1:
            linenr = linenr + 1
            line = str(zeile)
            lefthalf = line.split('#')
            self.entries.sort(cmp=self.__mycmp__, key=None, reverse=False)
            try:
                (name, address) =  lefthalf.pop(0).split()
                try:
                    ipad=IPv6Network(address)
                    if self.entries.count([name,ipad]) == 0:
                        self.entries.append([name,ipad])
                except:
                    print "User-Error: file:",filename
                    print "User-Error: line:",linenr
                    print "User-Error: content:",zeile
                    pass
                finally:
                    pass
            except:
                pass
        self.entries.sort(cmp=self.__mycmp__, key=None, reverse=False)

    def nice_print(title,mytext):
        """nice printout of a config line, only to impress the user
        used linelength: 70 characters"""
        rest_len = 78 - len(title) - len(mytext)
        print title + " " + mytext + " "*rest_len + "#"

    def append(self,filename):
        """append content of file to entries"""
        my_err = False
        try:
            self.__read_file(filename)
        except:
            msg = "error reading %s" % filename
            raise ValueError, msg
        
    def get_addrs(self,name):
        """return list of addresses belonging to a name"""
        addrs = []
        for entry in self.entries:
            (hname,addr) = entry
            if hname == name:
                addrs.append(addr)
        #addrs.sort(cmp=None, key=None, reverse=False) 
        return addrs

    def show_addr(self,name):
        """print addresses belonging to name"""
        if name == None:
            return
        mine = self.get_addrs(name)
        print name,mine
        
    def show_hostnet6(self):
        """show all current entries"""
        nice_print("# hostnet6 contents:",'')
        number = 0
        for entry in self.entries:
            number = number + 1
            (hname,addr) = entry
            nice_print( '#    '+str(hname),str(addr))
        s =  "# hostnet6: %5d entries found" % number
        nice_print(s,'')
        nice_print('#','')

#class IPaddr_test(unittest.TestCase):
#    """
#    dummy tests not neccessary here, not our class
#    """
#
#    #def test01(self):
#    #    return True

class HostNet6_tests(unittest.TestCase):
    '''some tests for class HostNet6'''

    def test_01_read_nonexisting_file(self):
        """
        read non existing file, check raise
        """
        my_err = False
        try:
            hn6 = HostNet6("non-existing-file")
        except:
            my_err = True
        self.assertTrue(my_err)
        
    def test_02_read_an_existing_file(self):
        """
        read an existing file, check no raise
        """
        my_err = False
        file = "reference-hostnet"
        try:
            hn6 = HostNet6(file)
        except:
            my_err = True
        self.assertFalse(my_err)

    def test_03_evaluate_entries(self):
        """
        evaluate entries of reference-hostnet
        """
        file = "reference-hostnet"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file)
            print hn6.entries
        except:
            my_err = True
        print content
        self.assertEquals(content, hn6.entries)

    def test_04_evaluate_appended_entries_fail(self):
        """
        evaluate appended entries of reference-hostnet-fail
        """
        file1 = "reference-hostnet"
        file2 = "reference-hostnet-fail"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file1)
        except:
            my_err = True
        try:
            hn6.append(file2)
        except:
            my_err = True
        self.assertTrue(my_err)
        #print "HN:", hn6.entries
        self.assertEquals(content, hn6.entries)

    def test_05_evaluate_appended_entries_ok(self):
        """
        evaluate entries of reference-hostnet-append
        """
        file1 = "reference-hostnet"
        file2 = "reference-hostnet-append"
        content = [ \
            ['any', IPv6Network('2000::/3')], \
            ['beaf', IPv6Network('2001:db8:beaf::/48')], \
            ['host-one', IPv6Network('2010:db8:1:beed::23/128')], \
            ['host-one', IPv6Network('2010:db8:1:beed::6/128')], \
            ['host-two', IPv6Network('2010:db8:1:beed::7/128')], \
            ['localhost', IPv6Network('::1/128')], \
            ['many', IPv6Network('::/0')]]
        my_err = False
        try:
            hn6 = HostNet6(file1)
            hn6.append(file2)
            print hn6.entries
        except:
            my_err = True
        self.assertEquals(content, hn6.entries)
        print "HA:", hn6.entries

if __name__ == "__main__":
        unittest.main()
