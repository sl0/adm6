#
# this is demo-module
# $LastChangedBy: Johannes Hubertz $
# $LastChangedDate: 2010-07-14 17:04:33 +0200 (Mi, 14. Jul 2010) $
# $Id: demo.py 51 2010-07-14 15:04:33Z Johannes Hubertz $
#
import os
import sys


def initiial_check():
    """Test if structure is present, if only parts exist, do
    not create the new one!!!
    """
    if os.environ.has_key('HOME'):
        home = os.environ.get('HOME')
    else:
        print u"No environment HOME defined, abort"
        sys.exit()
    pq = home + "/adm6"
    pe = pq + '/etc'
    pd = pq + '/desc'
    q = os.path.exists(pq)
    e = os.path.exists(pe)
    d = os.path.exists(pd)
    print "# last check before doing stupid ... "
    if q or e or d:
        """very last check before doing stupid"""
        print ""
        print "some requirements exist already, nothing touched"
        print ""
        print "??? perhaps you like to remove", pq, "???"
        sys.exit()
    print " passed now, still working ..."
    os.mkdir(pq)
    os.mkdir(pe)
    os.mkdir(pd)
    configuratio = init_adm6_conf(home + "/.adm6.conf")
    #print "READY: ", configuratio
    etc_hostnet6 = init_hostnet(pe)
    #print "READY: ", etc_hostnet6
    etc_rules_00 = init_rules(pe)
    debian_header = init_debian_headfoot(pe)
    openbsd_header = init_openbsd_headfoot(pe)
    #print "READY: ", etc_rules_00
    for machine in ('adm6', 'ns', 'www', 'r-ex', 'obi-wan'):
        path = pd+"/"+machine
        os.mkdir(path)
        os.symlink(etc_hostnet6, path + "/hostnet6")
        os.symlink(etc_rules_00, path + "/00-rules.admin")
        #print "READY: ",path
    #print "adm6 directory-structure created!"
    #print pd+"/ns"
    write_files_adm6(pd+"/adm6")
    write_files_www(pd+"/www")
    write_files_ns(pd+"/ns")
    #print pd+"/r-ex"
    write_files_r_ex(pd+"/r-ex")
    #print pd+"/obi-wan"
    write_files_obi_wan(pd+"/obi-wan")
    print "all directories, hostnet, rules, interface- "
    print "and routingtables created!"
    return True


def init_adm6_conf(file):
    c="""#
#
# global adm6 system configuration
#
[global]
# version of this software
version = 0.2
# this file written was written on:
timestamp = 2013-03-02
# residence of adm6 structure
home = /home/sl0/adm6/
# ssh-keys to connect to all the clients
key_file = none, please specify your own keyfile
# the following devices are adm6-clients
devices = adm6,r-ex,ns,,www,obi-wan
# which client OS are possibly supported
# f.e.: software = ['Debian', 'OpenBSD', 'WriteYourOwn']
software = ['Debian', 'OpenBSD', ]
#global debuglevel
debuglevel = 1

[device#adm6]
desc = our companies adm6 server
os = Debian GNU/Linux, wheezy
ip = 2001:db8:1:beed::23
fwd = 0
active = 1

[device#r-ex]
desc = external IPv6 router via ISP to the world
os = Debian GNU/Linux, wheezy
ip = 2001:db8:1:2::1
fwd = 1
active = 1

[device#ns]
desc = company dns server
os = Debian GNU/Linux, wheezy
ip = 2001:db8:1:2::23
fwd = 0
active = 1

[device#www]
desc = company web server
os = Debian GNU/Linux, Lenny
ip = 2001:db8:1:2::2013
fwd = 0
active = 1

[device#obi-wan]
desc = gif-tunnel for afiliate, internal end
os = OpenBSD 4.5
ip = 2001:db8:feed:2::1
fwd = 0
active = 1
"""
    write_any_file(file, c)
    return


def init_debian_headfoot(file):
    h="""#!/bin/bash
#
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   a d m 6   -   A Device Manager for IPv6 packetfiltering        ##"
echo "##                                                                  ##"
echo "##   version:      0.2                                              ##"
echo "##                                                                  ##"
echo "##   device-name:  cccccc                                           ##"
echo "##   device-type:  Debian GNU/Linux                                 ##"
echo "##                                                                  ##"
echo "##   date:         dddddd                                           ##"
echo "##   author:       Johannes Hubertz, hubertz-it-consulting GmbH     ##"
echo "##                                                                  ##"
echo "##   license:      GNU general public license version 3             ##"
echo "##                     or any later  version                        ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   some magic abbreviations follow                                ##"
echo "##                                                                  ##"
#
#POLICY_A='ACCEPT'
POLICY_D='DROP'
#
I6='/sbin/ip6tables '
IP6I='/sbin/ip6tables -A   input___new '
IP6O='/sbin/ip6tables -A   output__new '
IP6F='/sbin/ip6tables -A   forward_new '
#
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
for chain in $CHAINS
do
	/sbin/ip6tables -N ${chain}_act >/dev/null 2>/dev/null
	/sbin/ip6tables -N ${chain}_new
done
# but ignore all the boring fault-messages
$I6 -P   INPUT $POLICY_D
$I6 -P  OUTPUT $POLICY_D
$I6 -P FORWARD $POLICY_D
#
# some things need to pass,
# even if you don't like them
# do local and multicast on every interface
LOCAL="fe80::/10"
MCAST="ff02::/10"
# following was seen, it's mobile and we don't like them
# IN= OUT=eth1 SRC=0000:0000:0000:0000:0000:0000:0000:0000 DST=ff02:0000:0000:0000:0000:0000:0000:0016 LEN=76 TC=0 HOPLIMIT=1 FLOWLBL=0 PROTO=ICMPv6 TYPE=143 CODE=0
#  IN= OUT=eth1 SRC=fe80:0000:0000:0000:0200:24ff:fecc:220d DST=ff02:0000:0000:0000:0000:0000:0000:0016 LEN=96 TC=0 HOPLIMIT=1 FLOWLBL=0 PROTO=ICMPv6 TYPE=143 CODE=0
#
$IP6I -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
$IP6O -p ipv6-icmp -s ${LOCAL} -d ${LOCAL} -j ACCEPT
#
$IP6I -p ipv6-icmp -s ${MCAST} -j ACCEPT
$IP6I -p ipv6-icmp -d ${MCAST} -j ACCEPT
$IP6O -p ipv6-icmp -s ${MCAST} -j ACCEPT
#
# all prepared now, individual mangling and rules following
#
"""
    f="""#
#$IP6I -p tcp --dport 22 -j ACCEPT
#$IP6O -p tcp --sport 22 -j ACCEPT
#
# allow ping and pong always (al gusto)
#$IP6O -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6I -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
##
#$IP6I -p ipv6-icmp --icmpv6-type echo-request -j ACCEPT
#$IP6O -p ipv6-icmp --icmpv6-type echo-reply   -j ACCEPT
#
#ICMPv6types="${ICMPv6types} destination-unreachable"
ICMPv6types="${ICMPv6types} echo-request"
ICMPv6types="${ICMPv6types} echo-reply"
ICMPv6types="${ICMPv6types} neighbour-solicitation"
ICMPv6types="${ICMPv6types} neighbour-advertisement"
ICMPv6types="${ICMPv6types} router-solicitation"
ICMPv6types="${ICMPv6types} router-advertisement"
for icmptype in $ICMPv6types
do
	$IP6I -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
	$IP6O -p ipv6-icmp --icmpv6-type $icmptype -j ACCEPT
done
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j LOG  --log-prefix "unreach: " -m limit --limit 30/second --limit-burst 60
$IP6I -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT
#
CHAINS=""
CHAINS="$CHAINS input__"
CHAINS="$CHAINS output_"
CHAINS="$CHAINS forward"
#set -x
for chain in $CHAINS
do
	/sbin/ip6tables -E "${chain}_act" "${chain}_old"
	/sbin/ip6tables -E "${chain}_new" "${chain}_act"
done
#
$I6 -F INPUT
$I6 -A INPUT   -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 0 -j DROP
$I6 -A INPUT   -m rt --rt-type 2 -j LOG --log-prefix "rt-2: " -m limit --limit 3/second --limit-burst 6
$I6 -A INPUT   -m rt --rt-type 2 -j DROP
$I6 -A INPUT  -i lo -j ACCEPT
$I6 -A INPUT   --jump input___act
#
$I6 -F OUTPUT
$I6 -A OUTPUT -o lo -j ACCEPT
$I6 -A OUTPUT  --jump output__act
#
$I6 -F FORWARD
$I6 -A FORWARD -m rt --rt-type 0 -j LOG --log-prefix "rt-0: " -m limit --limit 3/second --limit-burst 6
$I6 -A FORWARD -m rt --rt-type 0 -j DROP
$I6 -A FORWARD --jump forward_act
#
for chain in $CHAINS
do
	/sbin/ip6tables -F "${chain}_old"
	/sbin/ip6tables -X "${chain}_old"
done
$I6 -F logdrop   >/dev/null 2>/dev/null
$I6 -X logdrop   >/dev/null 2>/dev/null
$I6 -N logdrop
$I6 -A   INPUT   --jump logdrop
$I6 -A  OUTPUT   --jump logdrop
$I6 -A FORWARD   --jump logdrop
$I6 -A logdrop -j LOG --log-prefix "drp: " -m limit --limit 3/second --limit-burst 6
$I6 -A logdrop -j DROP
#
/sbin/ip6tables-save -c >/root/last-filter
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##    End of generated filter-rules                                 ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
# EOF
"""
    hfile= file + "/Debian-header"
    ffile= file + "/Debian-footer"
    write_any_file(hfile,h)
    write_any_file(ffile,f)
    return

def init_openbsd_headfoot(file):
    h="""#!/bin/sh
#
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   a d m 6    -  a device manager for IPv6 packetfiltering        ##"
echo "##                                                                  ##"
echo "##   version:      0.2                                              ##"
echo "##                                                                  ##"
echo "##   device-name:  cccccc                                           ##"
echo "##   device-type:  OpenBSD pf.conf                                  ##"
echo "##                                                                  ##"
echo "##   date:         dddddd                                           ##"
echo "##   author:       Johannes Hubertz, hubertz-it-consulting GmbH     ##"
echo "##                                                                  ##"
echo "##   license:      GNU general public license version 3             ##"
echo "##                     or any later  version                        ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##   some magic abbreviations follow                                ##"
echo "##                                                                  ##"
#
cat << EOFEOFEOFEOF  > /tmp/new-pf-conf
# set default policy first
block all
#
"""
    f="""echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##    End of generated /tmp/new-pf-conf                             ##"
echo "##                                                                  ##"
echo "**********************************************************************"
EOFEOFEOFEOF
echo "**********************************************************************"
echo "**********************************************************************"
echo "##                                                                  ##"
echo "##    End of generated filter-rules                                 ##"
echo "##                                                                  ##"
echo "**********************************************************************"
echo "**********************************************************************"
# for some tests do a defaut policy accept (for now only)
# EOF
"""
    hfile= file + "/OpenBSD-header"
    ffile= file + "/OpenBSD-footer"
    write_any_file(hfile,h)
    write_any_file(ffile,f)
    return


def init_hostnet(path = ""):
    """write initial hostnet6 file"""
    full_filename = path + "/hostnet6"
    #print "writing initial hostnet to ", full_filename
    h = """#
# hostnet6
# $Id: demo.py 51 2010-07-14 15:04:33Z Johannes Hubertz $
#
any            2000::/3                            # Alle Welt
#any            ::/0                               # Alle Welt alternativ
many           ::/0                                # Alle Welt
localhost      ::1/128                             #
adm6           2010:db8:1:beed::23/128             # admin-computer
ns             2001:db8:1:2::53/128                # nameserver
ns             2001:db8:1:2::23/128                # nameserver
tester         2001:db8:1:fa00::/56                # per OpenVPN tunnel to r-ex
#tester         2001:db8:1:fb00::/56                # per OpenVPN
#tester         2001:db8:1:fc00::/56                # per OpenVPN
#tester         2001:db8:1:fd00::/56                # per OpenVPN
#tester         2001:db8:1:fe00::/56                # per OpenVPN
#tester         2001:db8:1:ff00::/56                # per OpenVPN
admin          2001:db8:1:2:216:d3ff:fec4:5174/128 # admin. host
admin          fe80:db8:1:2:216:d3ff:fec4:5174/128 # admin. host
linklocal      fe80::/10                           # on every interface
multicast      ff00::/8                            # on every interface
allhosts       ff00::1/128                         # on every interface possible!
allrouters     ff00::2/128                         # on every interface possible!
r-ex           2001:db8:1:2::1/128                 # internal, 2001:db8:1:2::/64 connected
r-ex           2001:db8:1::1/128                   # external, 2001:db8:1::/48 comes here
obi-wan        2001:db8:feed:2::1/28               # local end at affiliate
db8            2001:db8::/32                       # doku network
bad            2001:db8:bad::/48                   #  bad test and demo
abba           2001:db8:abba::/48                  # abba test and demo
baad           2001:db8:baad::/48                  # baad test and demo
beef           2001:db8:beef::/48                  # beef test and demo
dada           2001:db8:dada::/48                  # dada test and demo
dead           2001:db8:dead::/48                  # dead test and demo
deaf           2001:db8:deaf::/48                  # deaf test and demo
"""
    write_any_file(full_filename,h)
    return full_filename

def init_rules(path = ""):
    """wirte 00-rules.admin to adm6/etc"""
    full_filename = path + "/00-rules.admin"
    r = """# this is 00-rules.admin for demonstation only
#  first: some syntax error and an empty line

admin       obi-wan   tcp    22    accept   # 
any	    ns        udp    53    accept   NOSTATE # 
admin        ns       tcp    22    accept   # 
admin        r-ex     tcp    22    accept   # 
admin        obi-wan  tcp    22    accept   # 
admin       r-ex      tcp    22    accept   #
admin       ns        tcp    22    accept   # test options
admin       r-ex      tcp    22    accept   FORCED INSEC NOIF NOSTATE # test options
any         ns         udp    53    accept    NOSTATE      # test comment
ns          any        udp    53    accept    NOSTATE
any         ns         udp    53    accept    NOIF NOSTATE # test comment on rule 2
any         ns         tcp    25    accept                 # test comment
ns          any        tcp    25    accept                 # test comment
any         www        tcp    80    accept                 # test comment
jhx6        www        tcp    22    accept    # essential administrative rule!
nag          any        icmpv6    echo-request    accept
any          nag        icmpv6    echo-reply      accept
any          nag        icmpv6    destination-unreachable    accept
nag          any        tcp    0:    accept
many         www        tcp    80    accept
nag          www        tcp    80    accept
nag          www        tcp    25   accept
www          nag        tcp    113  accept
##
#r-ex        linklocal  icmpv6 echo-request  accept
#admin       allhosts   icmpv6 echo-request  accept
##
#many        allhosts   icmpv6 echo-request  accept
##
##jhx        srv        tcp    22    accept
##jhx        many       tcp    80    accept
##jhx        many       tcp    443    accept
###
#any         any        tcp    22    deny    # and no one else
#
#tester      tester     tcp    22    accept
#deaf        dada       udp     53   accept
#dada        deaf       udp     53   deny
#
#EOF
"""
    write_any_file(full_filename,r)
    return full_filename

def write_files_adm6(path):
    i="""eth0      Link encap:Ethernet  HWaddr 08:00:27:0d:1f:8f
          inet6 addr: 2010:db8:f002:beef::4711/64 Scope:Global
          inet6 addr: 2010:db8:f002:beef:a00:27ff:fe0d:1f8f/64 Scope:Global
          inet6 addr: fe80::a00:27ff:fe0d:1f8f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:849 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4058 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:86325 (84.3 KiB)  TX bytes:1192588 (1.1 MiB)
          Interrupt:11 Base address:0xd020

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
"""
    r="""2010:db8:f002:beef::/64 dev eth0  proto kernel  metric 256  expires 2591953sec mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev eth0  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
default via fe80::a00:27ff:fe59:d69e dev eth0  proto kernel  metric 1024  expires 1591sec mtu 1500 advmss 1440 hoplimit 64
"""
    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    return

def write_files_www(path):
    i="""eth0      Link encap:Ethernet  HWaddr 00:00:24:c3:e0:50
          inet addr:87.79.1.121  Bcast:87.79.1.127  Mask:255.255.255.240
          inet6 addr: fe80::200:24ff:fec3:e050/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2071381 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1423978 errors:10 dropped:0 overruns:10 carrier:10
          collisions:0 txqueuelen:1000
          RX bytes:170392035 (162.4 MiB)  TX bytes:1288496147 (1.2 GiB)
          Interrupt:16 Base address:0x2000

eth1      Link encap:Ethernet  HWaddr 00:00:24:c3:e0:51
          inet6 addr: 2010:db8:f002:1:200:24ff:fec3:e051/64 Scope:Global
          inet6 addr: fe80::200:24ff:fec3:e051/64 Scope:Link
          inet6 addr: 2010:db8:f002:1::2010/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1412  Metric:1
          RX packets:776009 errors:0 dropped:0 overruns:0 frame:0
          TX packets:787546 errors:9 dropped:0 overruns:9 carrier:9
          collisions:0 txqueuelen:1000
          RX bytes:73937942 (70.5 MiB)  TX bytes:296888864 (283.1 MiB)
          Interrupt:17 Base address:0x4000

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:3082 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3082 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:313661 (306.3 KiB)  TX bytes:313661 (306.3 KiB)
"""
    r="""2010:db8:f002:1::/64 dev eth1  metric 256  expires 2592054sec mtu 1412 advmss 1352 hoplimit 4294967295
2010:db8:f002:2::/64 via 2010:db8:f002:1::2 dev eth1  metric 1024  mtu 1412 advmss 1352 hoplimit 4294967295
2000::/3 via 2010:db8:f002:1::1 dev eth1  metric 1024  mtu 1412 advmss 1352 hoplimit 4294967295
fe80::/64 dev eth1  metric 256  mtu 1412 advmss 1352 hoplimit 4294967295
fe80::/64 dev eth0  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
default via fe80::200:24ff:fec4:d819 dev eth1  proto kernel  metric 1024  expires 1693sec mtu 1412 advmss 1352 hoplimit 64
"""
    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    return


def write_files_ns(path):
    i = """eth0      Link encap:Ethernet  HWaddr 00:00:24:cc:22:0c
          inet addr:87.79.1.114  Bcast:87.79.1.127  Mask:255.255.255.240
          inet6 addr: fe80::200:24ff:fecc:220c/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1412  Metric:1
          RX packets:7320840 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6617553 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:1003031819 (956.5 MiB)  TX bytes:1344136880 (1.2 GiB)
          Interrupt:11 Base address:0xe100

eth1      Link encap:Ethernet  HWaddr 00:00:24:cc:22:0d
          inet6 addr: 2010:db8:f002:1::23/64 Scope:Global
          inet6 addr: 2010:db8:f002:1:200:24ff:fecc:220d/64 Scope:Global
          inet6 addr: fe80::200:24ff:fecc:220d/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1412  Metric:1
          RX packets:308566 errors:0 dropped:0 overruns:0 frame:0
          TX packets:240255 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:89071803 (84.9 MiB)  TX bytes:24547988 (23.4 MiB)
          Interrupt:5 Base address:0xe200

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:734437 errors:0 dropped:0 overruns:0 frame:0
          TX packets:734437 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:228381858 (217.8 MiB)  TX bytes:228381858 (217.8 MiB)
"""
    r = """2010:db8:f002:1::/64 dev eth1  metric 256  expires 2592009sec mtu 1412 advmss 1352 hoplimit 4294967295
fe80::/64 dev eth0  metric 256  mtu 1412 advmss 1352 hoplimit 4294967295
fe80::/64 dev eth1  metric 256  mtu 1412 advmss 1352 hoplimit 4294967295
default via 2010:db8:f002:1::1 dev eth1  metric 1  mtu 1412 advmss 1352 hoplimit 4294967295
default via fe80::200:24ff:fec4:d819 dev eth1  proto kernel  metric 1024  expires 1648sec mtu 1412 advmss 1352 hoplimit 64
"""
    ms = """# adm6 Debian mangle6-startup starting
# if you like, put some commands in this file
# they are expected after firewall-setup is ready
# and before inserting all the rules
#
# typically some packet-manglin or the like
#
# nothing to mangle for now, have fun!
#
# mangle6-startup ends here
"""
    me = """# adm6 Debian mangle6-endup starting
# if you like, put some commands in this file
# they are expected after all rules are done
# but before firewall-finalizes
#
# nothing to mangle for now, have fun!
#
# mangle6-endup ends here
"""
    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    write_any_file(path+"/mangle-startup",ms)
    write_any_file(path+"/mangle-endup",me)
    return

def write_files_r_ex(path):
    i = """eth0      Link encap:Ethernet  HWaddr 00:00:24:c4:d8:18  
          inet addr:87.79.1.126  Bcast:87.79.1.127  Mask:255.255.255.240
          inet6 addr: fe80::200:24ff:fec4:d818/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:62828154 errors:0 dropped:0 overruns:0 frame:0
          TX packets:65705105 errors:9 dropped:0 overruns:9 carrier:9
          collisions:0 txqueuelen:1000 
          RX bytes:166374998 (158.6 MiB)  TX bytes:2988023236 (2.7 GiB)
          Interrupt:17 Base address:0xe000 

eth0:1    Link encap:Ethernet  HWaddr 00:00:24:c4:d8:18  
          inet addr:87.79.1.125  Bcast:87.79.1.127  Mask:255.255.255.240
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          Interrupt:17 Base address:0xe000 

eth0:2    Link encap:Ethernet  HWaddr 00:00:24:c4:d8:18  
          inet addr:87.79.1.113  Bcast:87.79.1.127  Mask:255.255.255.240
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          Interrupt:17 Base address:0xe000 

eth0:3    Link encap:Ethernet  HWaddr 00:00:24:c4:d8:18  
          inet addr:87.79.1.115  Bcast:87.79.1.127  Mask:255.255.255.240
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          Interrupt:17 Base address:0xe000 

eth1      Link encap:Ethernet  HWaddr 00:00:24:c4:d8:19  
          inet6 addr: fe80::200:24ff:fec4:d819/64 Scope:Link
          inet6 addr: 2010:db8:f002:1::1/64 Scope:Global
          inet6 addr: 2010:db8:f002:1::53/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1300  Metric:1
          RX packets:3165973 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3083693 errors:3 dropped:0 overruns:3 carrier:3
          collisions:0 txqueuelen:1000 
          RX bytes:1118052922 (1.0 GiB)  TX bytes:566086844 (539.8 MiB)
          Interrupt:18 Base address:0x2000 

eth2      Link encap:Ethernet  HWaddr 00:00:24:c6:fc:84  
          inet addr:87.79.1.102  Bcast:87.79.1.103  Mask:255.255.255.248
          inet6 addr: fe80::200:24ff:fec6:fc84/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:77713999 errors:0 dropped:0 overruns:0 frame:0
          TX packets:78500952 errors:16 dropped:0 overruns:16 carrier:16
          collisions:0 txqueuelen:1000 
          RX bytes:4128560908 (3.8 GiB)  TX bytes:2372215028 (2.2 GiB)
          Interrupt:18 Base address:0x4000 

eth3      Link encap:Ethernet  HWaddr 00:00:24:c6:fc:85  
          inet addr:192.168.0.2  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::200:24ff:fec6:fc85/64 Scope:Link
          inet6 addr: 2010:db8:f002::2/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:224314477 errors:0 dropped:2 overruns:0 frame:0
          TX packets:225044221 errors:13 dropped:0 overruns:13 carrier:13
          collisions:0 txqueuelen:1000 
          RX bytes:974816343 (929.6 MiB)  TX bytes:1079106738 (1.0 GiB)
          Interrupt:19 Base address:0x4000 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:4353 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4353 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:246583 (240.8 KiB)  TX bytes:246583 (240.8 KiB)

sit1      Link encap:IPv6-in-IPv4  
          inet6 addr: 2010:db8:f002:3::1/64 Scope:Global
          inet6 addr: fe80::574f:173/128 Scope:Link
          UP POINTOPOINT RUNNING NOARP  MTU:1480  Metric:1
          RX packets:5931194 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4491145 errors:84 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:542871043 (517.7 MiB)  TX bytes:2930595984 (2.7 GiB)

tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:ff00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:19828 errors:0 dropped:0 overruns:0 frame:0
          TX packets:20167 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:3499108 (3.3 MiB)  TX bytes:3911344 (3.7 MiB)

tun1      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:fe00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:2373 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

tun2      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:fd00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

tun3      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:fc00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:10882 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8428 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:1755640 (1.6 MiB)  TX bytes:1543804 (1.4 MiB)

tun4      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:fb00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:26403 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1211 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:4314584 (4.1 MiB)  TX bytes:114736 (112.0 KiB)

tun5      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet6 addr: fe80:0:fa00::1/64 Scope:Link
          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:2370 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
"""
    r = """2001:db8:1::/64 dev eth3  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:1::/64 dev eth1  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:2::/64 dev sit1  metric 1024  mtu 1480 advmss 1420 hoplimit 4294967295
2001:db8:1:3::/64 via :: dev sit1  metric 256  mtu 1480 advmss 1420 hoplimit 4294967295
2001:db8:1:fa00::/56 via fe80:0:fa00::2 dev tun0  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:fb00::/56 via fe80:0:fb00::2 dev tun1  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:fc00::/56 via fe80:0:fc00::2 dev tun2  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:fd00::/56 via fe80:0:fd00::2 dev tun3  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:fe00::/56 via fe80:0:fe00::2 dev tun4  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
2001:db8:1:ff00::/56 via fe80:0:ff00::2 dev tun5  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
unreachable 2001:db8:1::/48 dev lo  metric 1024  error -101 mtu 16436 advmss 16376 hoplimit 4294967295
2000::/3 via 2001:db8:1::1 dev eth3  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev eth1  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev eth0  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev eth2  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev eth3  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 via :: dev sit1  metric 256  mtu 1480 advmss 1420 hoplimit 4294967295
fe80::/64 dev tun0  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev tun1  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev tun2  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev tun3  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev tun4  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80::/64 dev tun5  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:fa00::/64 dev tun0  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:fb00::/64 dev tun1  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:fc00::/64 dev tun2  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:fd00::/64 dev tun3  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:fe00::/64 dev tun4  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
fe80:0:ff00::/64 dev tun5  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295
"""
    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    return

def write_files_obi_lan(path):
    i = """
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33204
        priority: 0
        groups: lo
        inet 127.0.0.1 netmask 0xff000000
        inet6 ::1 prefixlen 128
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x5
sis0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:c8:cf:04
        priority: 0
        groups: egress
        media: Ethernet autoselect (100baseTX full-duplex)
        status: active
        inet 192.168.110.176 netmask 0xffffff00 broadcast 192.168.110.255
        inet6 fe80::200:24ff:fec8:cf04%sis0 prefixlen 64 scopeid 0x1
        inet6 2001:db8:1:2::1 prefixlen 64
sis1: flags=8842<BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:c8:cf:05
        priority: 0
        media: Ethernet autoselect (none)
        status: no carrier
sis2: flags=8842<BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:c8:cf:06
        priority: 0
        media: Ethernet autoselect (none)
        status: no carrier
enc0: flags=0<> mtu 1536
        priority: 0
gif0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
        priority: 0
        groups: gif
        physical address inet 192.168.110.176 --> 87.79.1.115
        inet6 fe80::200:24ff:fec8:cf04%gif0 ->  prefixlen 64 scopeid 0x6
        inet6 2001:db8:1:3::2 -> 2001:db8:1:3::1 prefixlen 128
"""
    r = """Routing tables

Internet:
Destination        Gateway            Flags   Refs      Use   Mtu  Prio Iface
default            192.168.110.254    UGS        0  3637281     -     8 sis0
127/8              127.0.0.1          UGRS       0        0 33204     8 lo0
127.0.0.1          127.0.0.1          UH         1     6199 33204     4 lo0
192.168.110/24     link#1             UC         2        0     -     4 sis0
192.168.110.16     00:1c:25:d7:c0:dd  UHLc       1     4332     -     4 sis0
192.168.110.254    00:00:24:c8:72:ad  UHLc       1    14296     -     4 sis0
224/4              127.0.0.1          URS        0        0 33204     8 lo0

Internet6:
Destination                        Gateway                        Flags   Refs      Use   Mtu  Prio Iface
::/104                             ::1                            UGRS       0        0     -     8 lo0
::/96                              ::1                            UGRS       0        0     -     8 lo0
::1                                ::1                            UH        14        0 33204     4 lo0
::127.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0
::224.0.0.0/100                    ::1                            UGRS       0        0     -     8 lo0
::255.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0
::ffff:0.0.0.0/96                  ::1                            UGRS       0        0     -     8 lo0
2000::/3                           2001:db8:1:5afe::2         UGS        0    65934     -     8 gif0
2001:db8:1:2::/64              link#1                         UC         1        0     -     4 sis0
2001:db8:1:2::1                00:00:24:c8:cf:04              UHL        0        6     -     4 lo0
2001:db8:1:2:216:3eff:fe14:4b91 00:16:3e:14:4b:91              UHLc       0    12625     -     4 sis0
2001:db8:1:3::1                2001:db8:1:3::2            UH         0        4     -     4 gif0
2001:db8:1:3::2                link#6                         UHL        0        6     -     4 lo0
2001:db8:1:5afe::1             link#6                         UHL        0       12     -     4 lo0
2001:db8:1:5afe::2             2001:db8:1:5afe::1         UH         1      153     -     4 gif0
2002::/24                          ::1                            UGRS       0        0     -     8 lo0
2002:7f00::/24                     ::1                            UGRS       0        0     -     8 lo0
2002:e000::/20                     ::1                            UGRS       0        0     -     8 lo0
2002:ff00::/24                     ::1                            UGRS       0        0     -     8 lo0
fe80::/10                          ::1                            UGRS       0        0     -     8 lo0
fe80::%sis0/64                     link#1                         UC         2        0     -     4 sis0
fe80::200:24ff:fec8:cf04%sis0      00:00:24:c8:cf:04              UHL        1        0     -     4 lo0
fe80::216:3eff:fe14:4b91%sis0      00:16:3e:14:4b:91              UHLc       0    10950     -     4 sis0
fe80::21c:25ff:fed7:c0dd%sis0      00:1c:25:d7:c0:dd              UHLc       0     3502     -     4 sis0
fe80::%lo0/64                      fe80::1%lo0                    U          0        0     -     4 lo0
fe80::1%lo0                        link#5                         UHL        0        0     -     4 lo0
fe80::%gif0/64                     link#6                         UC         0        0     -     4 gif0
fe80::200:24ff:fec8:cf04%gif0      link#6                         UHL        0        0     -     4 lo0
fec0::/10                          ::1                            UGRS       0        0     -     8 lo0
ff01::/16                          ::1                            UGRS       0        0     -     8 lo0
ff01::%sis0/32                     link#1                         UC         0        0     -     4 sis0
ff01::%lo0/32                      ::1                            UC         0        0     -     4 lo0
ff01::%gif0/32                     link#6                         UC         0        0     -     4 gif0
ff02::/16                          ::1                            UGRS       0        0     -     8 lo0
ff02::%sis0/32                     link#1                         UC         0        0     -     4 sis0
ff02::%lo0/32                      ::1                            UC         0        0     -     4 lo0
ff02::%gif0/32                     link#6                         UC         0        0     -     4 gif0
"""
    ms = """# OpenBSD mangle6-startup starting
#
# if you like, put some commands in this file
# they are expected after firewall-setup is ready
# and before inserting all the rules
# 
# typically some packet-manglin or the like
#
# nothing to mangle for now, have fun!
#
# OpenBSD mangle6-startup ends here
"""
    me = """# OpenBSD mangle6-endup starting
#
# adm6 OpenBSD Mangling endup
# if you like, put some commands in this file
# they are expected after all rules are done
# but before firewall-finalizes
#
# nothing to mangle for now, have fun!
#
# OpenBSD mangle6-endup ends here
"""

    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    write_any_file(path+"/mangle-startup",ms)
    write_any_file(path+"/mangle-endup",me)
    return

def write_files_obi_wan(path):
    i = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33204
        priority: 0
        groups: lo
        inet 127.0.0.1 netmask 0xff000000
        inet6 ::1 prefixlen 128
        inet6 fe80::1%lo0 prefixlen 64 scopeid 0x5
sis0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:ca:1d:9c
        priority: 0
        media: Ethernet autoselect (100baseTX full-duplex)
        status: active
        inet6 2001:db8:1:1::2 prefixlen 64
        inet6 fe80::200:24ff:feca:1d9c%sis0 prefixlen 64 scopeid 0x1
sis1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:ca:1d:9d
        priority: 0
        media: Ethernet autoselect (100baseTX full-duplex)
        status: active
        inet 87.79.1.116 netmask 0xfffffff0 broadcast 87.79.1.127
        inet6 fe80::200:24ff:feca:1d9d%sis1 prefixlen 64 scopeid 0x2
sis2: flags=8842<BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        lladdr 00:00:24:ca:1d:9e
        priority: 0
        media: Ethernet autoselect (none)
        status: no carrier
enc0: flags=0<> mtu 1536
        priority: 0
gif0: flags=8050<POINTOPOINT,RUNNING,MULTICAST> mtu 1280
        priority: 0
        groups: gif
        physical address inet 87.79.1.116 --> 87.79.93.232
        inet6 2001:db8:1:5afe::2 -> 2001:db8:1:5afe::1 prefixlen 128
        inet6 fe80::200:24ff:feca:1d9c%gif0 ->  prefixlen 64 scopeid 0x6
"""
    r = """Routing tables

Internet:
Destination        Gateway            Flags   Refs      Use   Mtu  Prio Iface
87.79.1.96/29      87.79.1.113        UGS        1     3703     -     8 sis1
87.79.1.112/28     link#2             UC         2        0     -     4 sis1
87.79.1.113        00:00:24:c4:d8:18  UHLc       1        0     -     4 sis1
87.79.1.126        00:00:24:c4:d8:18  UHLc       1     1293     -     4 sis1
87.79.93.232       87.79.1.126        UGHS       0  1117324     -     8 sis1
127/8              127.0.0.1          UGRS       0        0 33204     8 lo0
127.0.0.1          127.0.0.1          UH         1     1733 33204     4 lo0
224/4              127.0.0.1          URS        0        0 33204     8 lo0

Internet6:
Destination                        Gateway                        Flags   Refs      Use   Mtu  Prio Iface
::/104                             ::1                            UGRS       0        0     -     8 lo0
::/96                              ::1                            UGRS       0        0     -     8 lo0
::1                                ::1                            UH        14        0 33204     4 lo0
::127.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0
::224.0.0.0/100                    ::1                            UGRS       0        0     -     8 lo0
::255.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0
::ffff:0.0.0.0/96                  ::1                            UGRS       0        0     -     8 lo0
2000::/3                           2001:db8:1:1::1            UGS        0      737     -     8 sis0
2001:db8:1:1::/64              link#1                         UC         3        0     -     4 sis0
2001:db8:1:1::1                00:00:24:c4:d8:19              UHLc       1    42132     -     4 sis0
2001:db8:1:1::2                00:00:24:ca:1d:9c              UHL        1      199     -     4 lo0
2001:db8:1:1::23               00:00:24:cc:22:0d              UHLc       0       13     -     4 sis0
2001:db8:1:1::53               00:00:24:c4:d8:19              UHLc       0    22464     -     4 sis0
2001:db8:1:2::/64              2001:db8:1:5afe::1         UGS        0    81789     -     8 gif0
2001:db8:1:5afe::1             2001:db8:1:5afe::2         UH         1       12     -     4 gif0
2001:db8:1:5afe::2             link#6                         UHL        0       20     -     4 lo0
2002::/24                          ::1                            UGRS       0        0     -     8 lo0
2002:7f00::/24                     ::1                            UGRS       0        0     -     8 lo0
2002:e000::/20                     ::1                            UGRS       0        0     -     8 lo0
2002:ff00::/24                     ::1                            UGRS       0        0     -     8 lo0
fe80::/10                          ::1                            UGRS       0       11     -     8 lo0
fe80::%sis0/64                     link#1                         UC         1        0     -     4 sis0
fe80::200:24ff:fec4:d819%sis0      00:00:24:c4:d8:19              UHLc       0   130103     -     4 sis0
fe80::200:24ff:feca:1d9c%sis0      00:00:24:ca:1d:9c              UHL        0        0     -     4 lo0
fe80::%sis1/64                     link#2                         UC         0        0     -     4 sis1
fe80::200:24ff:feca:1d9d%sis1      00:00:24:ca:1d:9d              UHL        0        0     -     4 lo0
fe80::%lo0/64                      fe80::1%lo0                    U          0        0     -     4 lo0
fe80::1%lo0                        link#5                         UHL        0        0     -     4 lo0
fe80::%gif0/64                     link#6                         UC         0        0     -     4 gif0
fe80::200:24ff:feca:1d9c%gif0      link#6                         UHL        0        0     -     4 lo0
fec0::/10                          ::1                            UGRS       0        0     -     8 lo0
ff01::/16                          ::1                            UGRS       0        0     -     8 lo0
ff01::%sis0/32                     link#1                         UC         0        0     -     4 sis0
ff01::%sis1/32                     link#2                         UC         0        0     -     4 sis1
ff01::%lo0/32                      ::1                            UC         0        0     -     4 lo0
ff01::%gif0/32                     link#6                         UC         0        0     -     4 gif0
ff02::/16                          ::1                            UGRS       0        0     -     8 lo0
ff02::%sis0/32                     link#1                         UC         0        0     -     4 sis0
ff02::%sis1/32                     link#2                         UC         0        0     -     4 sis1
ff02::%lo0/32                      ::1                            UC         0        0     -     4 lo0
ff02::%gif0/32                     link#6                         UC         0        0     -     4 gif0
"""
    write_any_file(path+"/interfaces",i)
    write_any_file(path+"/routes",r)
    return

def write_any_file(file,content):
    demo = True 
    if demo:
        # my version
        doku = content.replace('2001:db8:1:','2001:db8:23:')
    else:
        # demo version, db8
        doku = content.replace('2010:db8:f002:','2001:db8:0:')
    try:
        file = open(file,'w')
        file.write(doku)
        file.close()
    except:
        print "Fileoperation failed on file: ", file
        sys.exit()
    return file


def main():
    """create a testbed to check adm6
    only and only if no adm6 or details exist"""
    if initiial_check():
        print ""
        print "# start testing, it's up to you!"


if __name__ == "__main__":
    main()
