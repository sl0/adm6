#!/usr/bin/env python
#coding=utf-8
#
# all neccessary stuf about a device is handled here
#
#
# others packages
import os
import glob
import re
from ipaddr import IPv6Network, AddressValueError
from adm6configparser import Adm6ConfigParser
from hostnet6 import HostNet6
from filter6 import IP6_Filter

license="""
    adm6 is used to produce IPv6-Packetfilter configuration scripts
    for linux with ip6tables and OpenBSD with pf.conf, netsh,
    others are welcome to be implemented

    Copyright (C) 2011 - 2013 Johannes Hubertz

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Files belonging to adm6 are:
    device.py        contains main program and device-specific stuff
    filter6.py       contains stuff to create the filter-scripts
    adm6ConfigParser obviously contains configuration parsing
    hostnet6.py      reads definitions of hosts and networks

   Have fun!
"""

debuglevel = 0

class ThisDevice:
    """
    Object keeps all sampled information about a device,
    information is read from a subdirectory in adm6/desc/
    interface-config (output of ifconfig) and
    routing-table (output of ip -6 route show) and
    filter-rules (plain ascii-filese with defs and actions)
    might be useful for other things than generating filters
    """

    def __init__(self, device, confParser, hostnet):
        """
        create an instance of ThisdDevice representing an 
        IPv6 packet filtering machine, which is well configured 
        in .adm6.conf and in the machine homedirectory
        """
        self.name = device.strip()
        self.confParser = confParser
        self.device_os = confParser.get_os(device)
        self.device_ip = confParser.get_ip(device)
        self.device_fwd = confParser.get_fwd(device)
        self.device_asym = confParser.get_asym(device)
        #print "# Device:" + str(device) + " Found IP:" + str(self.device_ip)
        self.hn6 = hostnet
        self.interfaces = []
        self.interfaces_file = confParser.get_device_home(device).strip()
        self.interfaces_file = self.interfaces_file + '/interfaces'
        self.read_interface_file(self.interfaces_file)
        self.routingtab = []
        self.routingtab_file = confParser.get_device_home(device).strip()
        self.routingtab_file = self.routingtab_file + '/routes'
        self.read_routingtab_file(self.routingtab_file)
        self.rules_path = confParser.get_device_home(device).strip()
        self.rule_files = []
        self.rules = []

    def read_interface_file(self, filename):
        """read plain file containing output of
        Win-XP-SP3:  netsh, see adm6-ini.bat
        Debian:   ifconfig
        OpenBSD:  ifconfig
        """
        if len(filename) == 0:
            filename = self.interfaces_file
        try:
            f = open(filename, 'r')
            while True:
                line = f.readline()
                if not line:
                    break
                else:
                    pass
                self.interface_line(line)
            f.close()
            return False
        except IOError, e:
            print filename + ": ", e.strerror
            return True

    def interface_line(self, line):
        """evaluate one line of ifconfig-output
        store results in self.interfaces = []
        !!! specific on os-type !!!
        """
    #    if 'Win-XP' in self.device_os:
    #        """german version only for now"""
    #        if line.startswith('Schnittstelle '):
    #            righthalf = line.rsplit(':')
    #            ifacename = righthalf.pop(-1).strip()
    #            self.int_name = ifacename
    #        else:
    #            items = line.split()
    #            if len(items) > 1:
    #                targ = items.pop(-1)
    #                try:
    #                    target = IPv6Network(targ)
    #                except AddressValueError, e:
    #                    """no IPv6 Address in last column """
    #                    return
    #                self.int_addr = target
    #                self.interfaces.append([self.int_name, self.int_addr])
    #        return
        nam = re.findall('^[a-z]+[ 0-9][ :] ', line, flags=0)
        if nam:
            self.int_name = nam.pop(0).strip()
        add = []
        if 'Linux' in self.device_os:
            add = re.findall('\s*inet6\ .* Scope:*', line, flags=0)
            if add:
                ine = add.pop(0).split()
                adr = ine.pop(2)
                self.int_addr = IPv6Network(adr)
                self.interfaces.append([self.int_name, self.int_addr])
        if 'OpenBSD' in self.device_os:
            if 'inet6' in line:
                if '%' in line:
                    (le, ri) = line.split('%')
                else:
                    le = line
                ine = le.split()
                adr = ine.pop(1)
                self.int_addr = IPv6Network(adr)
                self.interfaces.append([self.int_name, self.int_addr])
            return

    def read_routingtab_file(self, filename=None):
        """read plain file containg output of
        Debian:     ip -6 route show
        OpenBSD:    route  -n   show
        """
        if len(filename) == 0:
            filename = self.routingtab_file
        self.routingtab = []
        try:
            f = open(filename, 'r')
            while True:
                line = f.readline()
                if not line:
                    break
                self.routingtab_line(line)
            f.close()
            return False
        except IOError, e:
            return True

    def routingtab_line(self, line):
        """read a line using os-spcific version
        """
        if 'Linux' in self.device_os:
            self._debian_routingtab_line(line)
        elif 'BSD' in self.device_os: 
            self._bsd_routingtab_line(line)
        #elif "Win-XP-SP3" in self.device_os:
        #    self._wxp_routingtab_line(line)
        else:
            raise "# error: Attempt to read routingtable for unknown OS"
        return

    def _debian_routingtab_line(self, line):
        """
        evaluate one line of debian ipv6 routingtable
        and append it to routingtab, which is a list of routing entries
        """
        words = line.split()
        w1 = words.pop(0).strip()
        if not line.find("unreachable"):
            return
        if not line.find("default") and line.find("via") > 0:
            target = '::/0'
            via = words.pop(1)
            interf = words.pop(2)
        else:
            target = w1
            if line.find("via") == -1:
                interf = words.pop(1)
                via = "::/0"
            else:
                via = words.pop(1)
                interf = words.pop(2)
        self.routingtab.append([IPv6Network(target),
                                IPv6Network(via), interf])

    def _bsd_routingtab_line(self, line):
        """evaluate one line of OpenBSD routing-table,
        enter only, if useful content"""
        zeile = line.split()
        #print "# rt-read: "+ str(zeile)
        if len(zeile) > 0:
            targ = zeile.pop(0)
            if not ":" in targ:
                #nice_print("# !!! IPv4 Exception reading routingtable",targ)
                return
            try:
                target = IPv6Network(targ)
            except:
                """no IPv6 Address in column one"""
                #nice_print("# !!! Exception reading routingtable",targ)
                return
            try:
                hop = zeile.pop(0)
                nhp = IPv6Network(hop.strip())
                nhp._prefixlen = 128
                dev = zeile.pop(-1)
                self.routingtab.append([target, nhp, dev])
                #print "APPEND:",str([target, nhp, dev])
                return
            except:
                #print " something wrong reading bsd-routingtable"
                return

    #def _wxp_routingtab_line(self, line):
    #    """evaluate one line of WinXP routing-table,
    #    enter only, if valid IPv6 content
    #    """
    #    zeile = line.split()
    #    if len(zeile) > 0:
    #        hop = zeile.pop(-1)
    #        if len(zeile) > 0:
    #            dev = zeile.pop(-1)
    #            target = zeile.pop(-1)
    #        else:
    #            return
    #    else:
    #        return
    #    try:
    #        targ = IPv6Network(target)
    #        nhp = IPv6Network(hop)
    #        self.routingtab.append([targ, nhp, dev])
    #    except:
    #        return
    #    return

    def read_rules(self):
        """
        read all the rule-files in a machines homedir
        """
        self.rules = []
        dir = self.rules_path
        os.chdir(dir)
        files = filter(os.path.isfile, glob.glob('[0-9]*rules*'))
        files.sort(cmp=cmp, key=None, reverse=False)
        for file in files:
            self.rule_files.append(file)
            self.read_rule_file(file)
        return len(self.rules)

    def read_rule_file(self, file):
        """
        read given file as rules for the machine
        """
        num = 0
        try:
            f = open(file, 'r')
            while True:
                line = f.readline()
                if not line:
                    break
                self.read_one_rule(line)
                num += 1
            f.close()
            return num
        except IOError, e:
            print file + ": ", e.strerror
        return num

    def read_one_rule(self, line):
        """
        take one line of a rules-file, check and do the appropriate
        """
        line = line.strip()
        line = line.replace("\t", " ")
        if line.__len__() < 8:
            #print "#Line to small"
            return
        if '#' in line:
            if line.startswith('#'):
                return
            (left, right) = line.split('#')
            rule = left.split()
        else:
            rule = line.split()
        try:
            src = rule.pop(0)
            dst = rule.pop(0)
            prot = rule.pop(0)
            port = rule.pop(0)
            actn = rule.pop(0)
            # options aren't neccessary!
        except:
            # found a line containing not enough elements
            # this shall be no fault, let the admin or the ui work correctly
            # or change the code
            return
        rule.insert(0, actn)
        rule.insert(0, prot)
        rule.insert(0, port)
        rule.insert(0, dst)
        rule.insert(0, src)
        self.rules.append(rule)

    def show_interfaces(self):
        """
        nice view of all interfacesconfiguration read
        """
        msg = nice_print('# Interfaces:', '')
        for interface in self.interfaces:
            (name, address) = interface
            msg += nice_print("#  "+name+':  ', str(address))
        return msg

    def show_routingtab(self):
        """
        nice view of all routingconfiguration read
        """
        msg = nice_print('# Routingtable:', '')
        msg += nice_print('#          [ target,                next_hop,',
                   '         interface ]')
        nr = 0
        for route in self.routingtab:
            nr = nr + 1
            msg += nice_print(u'# Route '+str(nr)+u':', str(route).strip())
        return msg

    def show_rules(self):
        """
        show all rules as text before addresses are solved
        """
        msg = ""
        rn = 1
        for rule in self.rules:
            msg += nice_print("#  "+str(rn)+": "+str(rule), '')
            rn += 1
        msg += nice_print('#', '')
        return msg

    def do_rules(self, filter):
        """invocation: dev.do_rules(filter)"""
        m = nice_print('# begin on rules expecting interface and routing for:',
            self.device_os)
        m += nice_print("#"*76, '#')
        rn = 0
        for rule in self.rules:
            rn += 1
            clone = str(rule)
            rule_header = u'# Rule '+str(rn)+u': '
            lstart = rule_header + "has  "+str(len(rule))+" items : "
            m += nice_print(lstart, '')
            m += nice_print(u'# '+str(rule), '')
            if len(rule) > 0:
                src = rule.pop(0)
            if len(rule) > 0:
                dst = rule.pop(0)
            if len(rule) > 0:
                pro = rule.pop(0)
            if len(rule) > 0:
                prt = rule.pop(0)
            if len(rule) > 0:
                act = rule.pop(0)
            else:
                m += nice_print(rule_header 
                        +"has insufficient parametercount", '')
                m += nice_print(rule_header + str(rule), '')
                continue
            self.do_this_rule(clone, rn, filter, rule_header,
                src, dst, pro, prt, act, rule)
            m += nice_print("#"*76, '#')
        m += nice_print('# '+self.name+u': ready, ' 
                        +str(rn)+u' rules found', '')
        filter.mach_output()

    def do_this_rule(self, clone, rn, filter6,
                        rh, sr, ds, pr, po, ac, op):
        """build os-independant detailed rule without options, which are
        very os-specific"""
        """Step 1: find IP-Addresses of Sources and Destinations,
        'de-grouping'"""
        fwrd = self.device_fwd
        srcs = self.hn6.get_addrs(sr)
        dsts = self.hn6.get_addrs(ds)
        rule_start_text = rh
        nice_print(rule_start_text +u'has  '+str(len(srcs))+" source(s) and "
                             +str(len(dsts))+" destination(s) in hostnet6", '')
        pair = 0
        """Step 2: Loop over all Source and Destination pairs"""
        for source in srcs:
            i_am_source = self.address_is_own(source)
            for destin in dsts:
                pair += 1
                i_am_destin = self.address_is_own(destin)
                (ifs, ros) = self.look_for(rn, source)
                (ifd, rod) = self.look_for(rn, destin)
                """Step 3: Which traffic is it?"""
                if i_am_source:
                    """Step 3a: This is outgoing traffic"""
                    nice_print(rule_start_text,
                        '  outgoing traffic!')
                elif i_am_destin:
                    """Step 3b: This is incoming traffic"""
                    nice_print(rule_start_text,
                        '  incoming traffic!')
                else:
                    """Step 3c: This is possibly traversing traffic"""
                    #print "ROS: " + str(ros) + " ROD: " + str(rod)
                    if ros == rod:
                        if not 'FORCED' in op:
                            nice_print(rule_start_text
                                +u'bypassing traffic, nothing done!', '')
                            continue
                            nice_print(rule_start_text
                                +u'bypassing traffic but FORCED', '')
                    else:
                        """We are sure about traversing traffic now"""
                        nice_print(rule_start_text
                            +u'traversing traffic, action needed', '')
                """Step 4: append appropriate filter"""
                filter6.append([clone, fwrd, rn, pair, i_am_source, i_am_destin,
                               source, destin, ifs, ros, ifd, rod,
                               pr, po, ac, op])
                #filter6.show_content()

    def look_for(self, rh, addr):
        """seeks addr in routing-table, returns tuple of
        interface-name and number of routing-entry"""
        interface = u'undef'
        route_number = -1
        ad = IPv6Network(addr)
        #print "LOOK_for: " + str(ad),
        for route in self.routingtab:
            route_number += 1
            (rte, nhp, dev) = route
            result = rte.__contains__(ad)
            if result:
                interface = dev
                #print "RETURN1: " + str(interface) + " Line: "+ str(route_number)
                return (interface, route_number)
        #print "RETURN2: " + str(interface) + " Line: "+ str(route_number)
        return (interface, route_number)

    def address_is_own(self, value):
        """check, if given address is interface-address of ThisDevice
        returns Name of Interface or None"""
        for interface in self.interfaces:
            [iface_name, target_IP] = interface
            target = IPv6Network(target_IP)
            if target.ip == value.ip:
                return iface_name
        return None

def nice_print(title, mytext):
    """
    nice printout of a config line, only to impress the user
    used linelength: 80 characters
    """
    rest_len = 78 - len(title) - len(mytext)
    message = title + " " + mytext + " "*rest_len + u"#\n"
    return message


def do_all_configured_devices():
    confParser = Adm6ConfigParser(".adm6.conf")
    version = confParser.get_version()
    confParser.print_header()
    ##confParser.inc_adm6_debuglevel()
    debuglevel = confParser.get_adm6_debuglevel()
    #print confParser.get_show_cf()
    my_devices = confParser.get_devices().split(',')
    print "# DEVICES: " + str(my_devices)
    for device_name in my_devices:
        if confParser.get_apply(device_name):
            device_os = confParser.get_os(device_name)
            confParser.print_head(device_name)
            path = str(confParser.get_device_home(device_name))
            h_path = path+'/hostnet6'
            hn6 = HostNet6(h_path)
            dev = ThisDevice(device_name, confParser, hn6)
            dev.read_rules()
            #hn6.show_hostnet6()
            #dev.show_interfaces()
            #dev.show_routingtab()
            dev.show_rules()
            #print "dev.device_fwd: ", dev.device_fwd,
            filter6 = IP6_Filter(debuglevel,
                         path,
                         device_name,
                         device_os,
                         dev.device_fwd,
                         dev.device_asym,
                         dev.interfaces)
            dev.do_rules(filter6)
            #filter6.mach_output(version)
    print "#"*80


if __name__ == "__main__":
    do_all_configured_devices()
