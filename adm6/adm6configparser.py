#! /usr/bin/env python
#coding=utf-8
"""
Module provides configration items of adm6

Instance is used for the handling of all configuration
aspects of adm6 and for looking printouts somehow pretty

Writing the config is not recommended now because of
unpredicable kind of sorting in the resulting file,
thats rather ugly
"""

import os
from ConfigParser import ConfigParser


class Adm6ConfigParser(ConfigParser):
    """
    Read global configuration from configfile named as parameter
    """

    def __init__(self, cfg_file):
        """
        initial read of config file
        """
        ConfigParser.__init__(self)
        self.homedir = os.getenv("HOME")
        #self.filename = self.homedir + cfg_file
        self.filename = os.path.join(self.homedir, cfg_file)
        self.cfp = ConfigParser()
        msg = "File not found: %s" % (self.filename)
        try:
            file = open(self.filename,'r')
            content = file
            file.close()
        except:
            raise ValueError, msg
        self.cfp.read([self.filename])

    def get_show_cf(self):
        """
        return complete content as dict of dicts
        """
        retstr = ""
        for section in self.cfp.sections():
            retstr += str(section)
            retstr += str(self.cfp.items(section)) + '\n'
        return retstr

    def get_adm6_home(self):
        """return adm6 homedir as read from config-file"""
        return self.cfp.get('global', 'home', False, {})

    def get_adm6_debuglevel(self):
        """get applicationwide debuglevel"""
        level = int(self.cfp.get('global', 'debuglevel', False, {}))
        return level

    def set_adm6_debuglevel(self, level):
        """set applicationwide debuglevel"""
        self.cfp.set('global', 'debuglevel', str(level))
        with open(self.filename, 'wb') as configfile:
            self.cfp.write(configfile)
        configfile.close()
        return True

    def dec_adm6_debuglevel(self):
        """decrement debuglevel by one"""
        level = int(self.get_adm6_debuglevel()) - 1
        if level < 0:
            level = 0
        self.set_adm6_debuglevel(str(level))
        return True

    def inc_adm6_debuglevel(self):
        """increment debuglevel"""
        level = int(self.get_adm6_debuglevel())
        level = level + 1
        self.set_adm6_debuglevel(str(level))
        return True

    def get_apply(self, device):
        """give back applyflag (missing flag means true always!)"""
        section = "device#" + device.strip()
        return self.cfp.getboolean(section, 'active')

    def get_version(self):
        """return version string read from config-flie"""
        #return self.cfp.get('global', 'version').strip()
        return self.cfp.get('global', 'version')

    def get_key_filename(self):
        """return ssh key_file read from config-flie"""
        return self.cfp.get('global', 'key_file')

    def get_devices(self):
        """give a list of all devices named in global section"""
        return self.cfp.get('global', 'devices', False, {})

    def get_software(self):
        """give a list of all os-software named in global section"""
        return self.cfp.get('global', 'software', False, {})

    def get_device_home(self, device):
        """give directory of device as full pathname"""
        pat = self.get_adm6_home()
        pat = pat.strip() +'desc/' + device.strip()
        return pat

    def get_desc(self, device):
        """give description of named device"""
        section = "device#" + device.strip()
        return self.cfp.get(section, 'desc')

    def get_os(self, device):
        """give OS-String of named device"""
        section = "device#" + device.strip()
        return self.cfp.get(section, 'os')

    def get_ip(self, device):
        """give IP of named device"""
        section = "device#" + device
        return self.cfp.get(section, 'ip')

    def get_fwd(self, device):
        """give back fwdflag (false means device does not forward IPv6!)"""
        section = "device#" + device.strip()
        fwd = False
        if self.cfp.has_section(section):
            if self.cfp.has_option(section, 'fwd'):
                fwd = self.cfp.get(section, 'fwd')
        return fwd > 0

    def get_asym(self, device):
        """give back asymmetric-flag
        (true means device does asymmetric IPv6 routing!)
        asymmetric = 1 forces stateful to off
        """
        section = "device#" + device.strip()
        asym = False
        if self.cfp.has_section(section):
            if self.cfp.has_option(section, 'asymmetric'):
                asym = self.cfp.get(section, 'asymmetric')
        return asym > 0

    def print_head(self, device):
        """
        print a nice header for named device-section
        """
        msg = "#"*80
        msg += '\n'
        msg += self.nice_print('#', '')
        msg += self.nice_print("# Device:      ", device.strip())
        msg += self.nice_print('#', '')
        msg += self.nice_print('# Desc:        ', self.get_desc(device.strip()))
        msg += self.nice_print('# OS:          ', self.get_os(device.strip()))
        msg += self.nice_print('# IP:          ', self.get_ip(device.strip()))
        msg += self.nice_print('# Forwarding:  ', 
                str(self.get_fwd(device.strip())))
        msg += self.nice_print('# Asymmetric:  ', 
                str(self.get_asym(device.strip())))
        msg += self.nice_print('#', '')
        msg += "#"*80
        return msg

    def print_header(self):
        """
        print nice header as top of every generated output
        """
        msg = "#"*80
        msg += '\n'
        msg = "#"*80
        msg += '\n'
        msg += self.nice_print('#', '')
        msg += self.nice_print('#', '')
        msg += self.nice_print('# adm6:      ', 'Packetfilter generator for')
        msg += self.nice_print('#            ', 'Linux ip6tables and OpenBSD pf.conf')
        msg += self.nice_print('#', '')
        msg += self.nice_print('# License:   ', 'GPLv3 - General Public License version 3')
        msg += self.nice_print('#          ', '                    or any later version')
        msg += self.nice_print('#', '')
        msg += self.nice_print('#', '')
        myversion = self.cfp.get('global', 'version')
        msg += self.nice_print('# Version:   ', myversion)
        config_timestamp = self.cfp.get('global', 'timestamp')
        msg += self.nice_print('# Date:      ', config_timestamp)
        msg += self.nice_print('# Author:    ', 'Johannes Hubertz')
        msg += self.nice_print('#', '')
        msg += self.nice_print('# Configuration of almost everything: ',
            self.filename.strip())
        msg += self.nice_print('#', '')
        msg += self.nice_print('# Copyright: ',
                         '(c)2011-2013 Johannes Hubertz, '+
                         'Cologne, Germany, Europe, Earth')
        msg += self.nice_print('#', '')
        msg += self.nice_print('#', '')
        msg += "#"*80
        return msg

    def print_all_headers(self):
        """
        print all device headers (for debug purposes only)
        """
        headers = self.print_header() + '\n'
        mydevs = self.get_devices().split(',')
        for device in mydevs:
            if self.get_apply(device):
                headers += self.print_head(device)
                headers += '\n'
        return headers

    def nice_print(self, title, mytext):
        """nice printout of a config line, only to impress the user
        used linelength: 70 characters"""
        rest_len = 78 - len(title) - len(mytext)
        msg =  title + " " + mytext + " "*rest_len + "#"
        return msg + '\n'


#if __name__ == "__main__":
#    CNF = Adm6ConfigParser(".adm6.conf")
#    print "main test program"
#    print dir(CNF)
#    print CNF.print_all_headers()
