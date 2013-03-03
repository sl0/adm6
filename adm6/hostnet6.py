#!/usr/bin/env python
#encoding:utf8
#
# file:    hostnet6.py
# author: sl0
# date:   2013-03-03
#

import unittest
from ipaddr import IPv6Network


class HostNet6(IPv6Network):
    """Instance is content of hostnet6-file
    as a sorted list of lists of: (name,address!!!es!!!)
    every line in file may be like:
    NAME   ADDRESS # COMMENT
                or
    # COMMENT
    """
    def __init__(self, file="reference-hostnet"):
        """read file into self.entries"""
        self.entries = []
        self.__read_file(file)

    def __mycmp__(self, l1, l2):
        """zum sortieren der Liste von [[name,adresse]]"""
        (n1,a1) = l1
        (n2,a2) = l2        
        return cmp(n1, n2)

    def __read_file(self, filename):
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

    def append(self, filename):
        """append content of file to entries"""
        my_err = False
        try:
            self.__read_file(filename)
        except:
            msg = "error reading %s" % filename
            raise ValueError, msg
        
    def get_addrs(self, name):
        """return list of addresses belonging to a name"""
        addrs = []
        for entry in self.entries:
            (hname,addr) = entry
            if hname == name:
                addrs.append(addr)
        #addrs.sort(cmp=None, key=None, reverse=False) 
        return addrs

    def show_addr(self, name):
        """print addresses belonging to name"""
        mine = self.get_addrs(name)
        print name,mine
        return (name, mine)
        
    def nice_print(self, title, mytext):
        """nice printout of a config line, only to impress the user
        used linelength: 70 characters"""
        rest_len = 78 - len(title) - len(mytext)
        returnval = title + " " + mytext + " "*rest_len + "#"
        print returnval
        return returnval
    
    def show_hostnet6(self):
        """show all current entries"""
        line = self.nice_print("# hostnet6 contents:",'')
        line += '\n'
        number = 0
        for entry in self.entries:
            number = number + 1
            (hname,addr) = entry
            line += self.nice_print('#    ' + str(hname), str(addr))
            line += '\n'
        s =  "# hostnet6: %5d entries found" % number
        line += self.nice_print(s,'')
        line += '\n'
        line += self.nice_print('#','')
        line += '\n'
        return line

