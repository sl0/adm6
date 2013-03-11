# -*- utf8

import time
from UserDict import UserDict


class Ip6_Filter_Rule(UserDict):
    """
    IP6_Filter_Rule is a container with all the neccessary stuff
    for device-type independant filter-generation.
    It is filled by reading all the specific device-files of one device,
    device-type is one out of (Debian, OpenBSD, OpenSolaris)
    interfaces, routing-table, hostnet6 and all device-rules
    """

    def __init__(self, dict=None, **kwargs):
        """
        set initial params valid for all instances, and create a
        DisplayList for representation of this Object
        """
        UserDict.__init__(self, dict, **kwargs)
        #self['debuglevel'] = 0
        self.msg = ""
        self['travers'] = False
        self['i_am_s'] = False
        self['i_am_d'] = False
        self['noif'] = False
        self['nonew'] = False
        self['nostate'] = False
        self['insec'] = False
        self['sport'] = u'1024:'
        # we cannot print f.e. a filedescriptor
        self.NeverDisplay = ['Output', 'debuglevel']
        # normal output not verbose
        self.CommentList = [
            'Rule-Nr',
            'Pair-Nr',
            'RuleText',
            ]
        self.DisplayList = [
            # meta-info
            'Rule-Nr', 'Pair-Nr', 'System-Name', 'System-Forward', 'OS',
            'Asymmetric',
            # user-given rule-info
            'RuleText',
            'Source', 'Destin', 'Protocol', 'sport', 'dport', 'Action',
            'nonew', 'noif', 'nostate', 'insec',
            # caclulated info
            'i_am_s', 'i_am_d', 'travers',
            'source-if', 'source-rn', 'src-linklocal', 'src-multicast',
            'destin-if', 'destin-rn', 'dst-linklocal', 'dst-multicast',
            ]
        return

    def __repr__(self):
        """representaion of Rule-Object for printouts"""
        retStr = u''
        if self['debuglevel']:
            reprList = self.DisplayList
        else:
            reprList = self.CommentList
        # sample the wellknown keys of DisplayList first
        for key in reprList:
            try:
                s = u"# %-15s: %-59s #\n" % (key, self[key])
            except:
                continue
            retStr += s
        # unsorted keys at last
        for key in dict(self):
            s = u''
            try:
                if key in self.NeverDisplay:
                    s = u"# %-15s: %-59s #\n" % (key, str(self['key']))
                elif not key in self.DisplayList:
                    s = u"# %-15s: %-59s #\n" % (key, self[key])
            except:
                continue
            retStr +=s
        return retStr

    def produce(self, outfile):
        self.msg = ""
        if 'Debian' in self['OS']:
            self.produce_Debian(outfile, False)
        elif 'OpenBSD' in self['OS']:
            self.produce_OpenBSD(outfile, False)
        elif 'BSD' in self['OS']:
            self.produce_IPF(outfile, False)
        elif 'Win-XP-SP3' in self['OS']:
            #self.produce_Debian(outfile, True)
            self.produce_wxpsp3(outfile, False)
        elif 'OpenSolaris' in self['OS']:
            self.produce_Debian(outfile, True)
            self.produce_IPF(outfile, False)
        else:
            msg = "Cannot make filter commands for unknown OS: %s!" \
                % (self['OS'])
            raise ValueError, msg
        return

    def produce_Debian(self, outfile, commented):
        """
        do one pair of src-dst out of a rule for Debian
        """
        #print u"# producing ip6tables commands for rule:", self['Rule-Nr'],
        #print u"Pair: ", self['Pair-Nr']
        rule_pair = "%d,%d" % (self['Rule-Nr'], self['Pair-Nr'])
        rule_id = u' -m comment --comment "' + rule_pair + u'"'
        answer_packets = False
        icmp_type = False
        proto = str(self['Protocol']).strip()
        # tcp, udp, and with esp we want bidirectional traffic, too!
        if proto in ['tcp', 'udp', 'esp']:
            answer_packets = True
        #icmpv6 has no states!
        if proto in ['icmpv6']:
            self['nostate'] = True
            icmp_type = True
        st_new = " -m state --state NEW,ESTABLISHED,RELATED"
        st_ans = " -m state --state     ESTABLISHED,RELATED"
        if self['nonew']:
            st_new = st_ans
        if self['nostate']:
            st_new = ""
            st_ans = ""
        if u'accept' in self['Action']:
            act = u' -j ACCEPT'
        elif u'reject' in self['Action']:
            act = u' -j REJECT'
            addition = u'''
/sbin/ip6tables -A   input___new  -i eth1 -s ::/0 -d 2001:4dd0:f002:1::23/128 -p tcp --sport 1024: --dport 54 -m state --state NEW,ESTABLISHED,RELATED -j REJECT --reject-with port-unreach
/sbin/ip6tables -A   output__new  -o eth1 -d ::/0 -s 2001:4dd0:f002:1::23/128 -p icmpv6 --icmpv6-type port-unreachable -j ACCEPT
/sbin/ip6tables -A   input___new  -i eth1 -s ::/0 -d 2001:4dd0:f002:1::23/128 -p tcp --sport 1024: --dport 54 -m state --state NEW,ESTABLISHED,RELATED -j REJECT --reject-with port-unreach
/sbin/ip6tables -A   output__new  -o eth1 -d ::/0 -s 2001:4dd0:f002:1::23/128 -p icmpv6 --icmpv6-type port-unreachable -j ACCEPT
'''
        else:
            act = u' -j DROP'
        # we have here and remote (hxxx, ryyy), protocol is uniqe
        hsrc = " -s " + str(self['Source'])
        rsrc = " -d " + str(self['Source'])
        hdst = " -d " + str(self['Destin'])
        rdst = " -s " + str(self['Destin'])
        dprt = " --dport " + str(self['dport'])
        rprt = " --sport " + str(self['dport']) # answers come from this port
        prot = " -p " + str(self['Protocol'])
        if self['insec']:
            spo = " --sport 0: "
            rpo = " --dport 0: "
        else:
            spo = " --sport " + str(self['sport'])
            rpo = " --dport " + str(self['sport'])
        if icmp_type:
            spo = ""
            rpo = ""
            rprt = ""
            dprt = " --icmpv6-type " + str(self['dport'])
        #ip6 has no states!
        if proto in ['ip6']:
            prot = ""
            spo = ""
            rpo = ""
            dprt = ""
            rprt = ""
            st_new = ""
            st_ans = ""
        line1 = hsrc + hdst + prot + spo + dprt + st_new + act
        line2 = rsrc + rdst + prot + rpo + rprt + st_ans + act
        #
        comm = ""
        if commented:
            comm = u"#"
        ipi = comm + "/sbin/ip6tables -A   input___new "
        ipo = comm + "/sbin/ip6tables -A   output__new "
        ipf = comm + "/sbin/ip6tables -A   forward_new "
        if self['noif']:
            sif = ""
            dif = ""
        else:
            sif = " -i "+ str(self['destin-if'])
            dif = " -o "+ str(self['destin-if'])
        if self['i_am_s']:
            #if self['dst-linklocal']:
            #    return
            self.msg += ipo + dif +line1 + rule_id + u'\n'
            outfile.write(ipo + dif + line1 + rule_id + u'\n')
            if answer_packets:
                self.msg += ipi + sif + line2 + rule_id + '\n'
                outfile.write(ipi + sif + line2 + rule_id + u'\n')
            self.msg += 'echo -n ".";'
            outfile.write(u'echo -n ".";')
        if self['i_am_d']:
            self.msg +=   ipi + sif + line1 + rule_id + '\n'
            outfile.write(ipi + sif + line1 + rule_id + u'\n')
            if answer_packets:
                self.msg += ipo + dif + line2 + rule_id + '\n'
                outfile.write(ipo + dif + line2 + rule_id + u'\n')
            self.msg += 'echo -n ".";'
            outfile.write(u'echo -n ".";')
        if not self['System-Forward']:
            if not self['forced']:
                self.msg = "# System-Forward: False ==> no rule generated"
                return
        if self['travers']:
            sif = ""
            dif = ""
            if not self['noif']:
                if not u'undef' in self['source-if']:
                    sif = " -i "+ str(self['source-if'])
                if not u'undef' in self['destin-if']:
                    dif = " -o "+ str(self['destin-if'])
            if self['src-linklocal'] or self['dst-linklocal']:
                self.msg = "# link-local ==> no forward"
                return  # Is this true? no forward traffic, link-local address!
            self.msg += ipf + sif + line1 + rule_id + '\n'
            outfile.write(ipf + sif + line1 + rule_id + u'\n')
            if answer_packets:
                self.msg += ipf + dif + line2 + rule_id + '\n'
                outfile.write(ipf + dif + line2 + rule_id + u'\n')
            self.msg += 'echo -n ".";'
            outfile.write(u'echo -n ".";')
        return

    def produce_OpenBSD(self, outfile, commented):
        """
        do one pair of src-dst out of a rule for OpenBSD
        """
        #print u"# producing pf_conf commands for rule:", self['Rule-Nr'],
        #print u"Pair: ", self['Pair-Nr']
        ########################################################################
        answer_packets = False
        icmp_type = False
        proto = str(self['Protocol']).strip()
        # tcp, udp, and with esp we want bidirectional traffic, too!
        if proto in ['tcp', 'udp', 'esp']:
            answer_packets = True
        #icmpv6 has no states!
        if proto in ['icmpv6']:
            self['nostate'] = True
            icmp_type = True
        #st_new = " -m state --state NEW,ESTABLISHED,RELATED"
        #st_ans = " -m state --state     ESTABLISHED,RELATED"
        st_ans = ""
        if self['nonew']:
            st_new = st_ans
        # Dirk M.: state erledigt Antwortpakete gleich mit.
        if self['nostate']:
            st_new = ""
            st_ans = ""
        else:
            st_new = " state "
            st_ans = " state "
            answer_packets = False
        if u'accept' in self['Action']:
            act = u'pass '
        elif u'reject' in self['Action']:
            act = u'drop '
            addition = u'''
/sbin/ip6tables -A   input___new  -i eth1 -s ::/0 -d 2001:4dd0:f002:1::23/128 -p tcp --sport 1024: --dport 54 -m state --state NEW,ESTABLISHED,RELATED -j REJECT --reject-with port-unreach
/sbin/ip6tables -A   output__new  -o eth1 -d ::/0 -s 2001:4dd0:f002:1::23/128 -p icmpv6 --icmpv6-type port-unreachable -j ACCEPT
/sbin/ip6tables -A   input___new  -i eth1 -s ::/0 -d 2001:4dd0:f002:1::23/128 -p tcp --sport 1024: --dport 54 -m state --state NEW,ESTABLISHED,RELATED -j REJECT --reject-with port-unreach
/sbin/ip6tables -A   output__new  -o eth1 -d ::/0 -s 2001:4dd0:f002:1::23/128 -p icmpv6 --icmpv6-type port-unreachable -j ACCEPT
'''
        else:
            act = u'drop '
        # we have here and remote (hxxx, ryyy), protocol is uniqe
        hsrc = " from " + str(self['Source'])
        rsrc = " to   " + str(self['Source'])
        hdst = " to   " + str(self['Destin'])
        rdst = " from " + str(self['Destin'])
        dprt = " port    " + str(self['dport'])
        rprt = " port    " + str(self['dport']) # answers come from this port
        prot = " proto " + str(self['Protocol'])
        if self['insec']:
            spo = " --sport 0: "
            rpo = " --dport 0: "
        else:
            spo = " --sport " + str(self['sport'])
            rpo = " --dport " + str(self['sport'])
        if icmp_type:
            spo = ""
            rpo = ""
            rprt = ""
            dprt = " --icmpv6-type " + str(self['dport'])
        #ip6 has no states!
        if proto in ['ip6']:
            prot = ""
            spo = ""
            rpo = ""
            dprt = ""
            rprt = ""
            st_new = ""
            st_ans = ""
        #line1 = hsrc + hdst + prot + spo + dprt + st_new + act
        #line2 = rsrc + rdst + prot + rpo + rprt + st_ans + act
        line1 = act + u" in quick " + hsrc + hdst + dprt + prot + st_new
        line2 = act + u"out quick " + rsrc + rdst +        prot + st_ans
        #
        comm = u""
        if commented:
            comm = u"#"
        ipi = comm #+ "/sbin/ip6tables -A   input___new "
        ipo = comm #+ "/sbin/ip6tables -A   output__new "
        ipf = comm #+ "/sbin/ip6tables -A   forward_new "
        if not self['System-Forward'] and self['travers']:
            self.msg = "# System does not forward by configuration"
            return
        if self['travers'] or self['i_am_s'] or self['i_am_d']:
            if self['noif']:
                sif = ""
                dif = ""
            else:
                sif = ""# -i "+ str(self['destin-if'])
                dif = ""# -o "+ str(self['destin-if'])
            if self['dst-linklocal']:
                self.msg = "# dst-link-local ==> no filter rule generated"
                return
            print ipo + dif + line1
            outfile.write(ipo + dif + line1 + u'\n')
            #if answer_packets:
            #    print ipi + sif + line2
            #    outfile.write(ipi + sif + line2 + u'\n')
        #self.msg = ipi + sif + line2
        self.msg = "# OpenBSD implementation _not_ ready!"
        return

    def produce_wxpsp3(self, outfile, commented):
        """
        do one pair of src-dst out of a rule for Win-XP-SP3
        """
        #print u"# producing netsh commands for rule:", self['Rule-Nr'],
        #print u"Pair: ", self['Pair-Nr']
        ########################################################################
        answer_packets = False
        icmp_type = False
        proto = str(self['Protocol']).strip()
        # tcp, udp, and with esp we want bidirectional traffic, too!
        if proto in ['tcp', 'udp', 'esp']:
            answer_packets = True
        #icmpv6 has no states!
        if proto in ['icmpv6']:
            self['nostate'] = True
            icmp_type = True
            # netsh firewall set icmpsetting 8 ENABLE
        st_ans = ""
        if self['nonew']:
            st_new = st_ans
        if self['nostate']:
            st_new = ""
            st_ans = ""
        else:
            st_new = " state "
            st_ans = " state "
            #answer_packets = False
        if u'accept' in self['Action']:
            act = u'pass '
        elif u'reject' in self['Action']:
            act = u'drop '
        else:
            act = u'drop '
        # we have here and remote (hxxx, ryyy), protocol is uniqe
        hsrc = " from " + str(self['Source'])
        rsrc = " to   " + str(self['Source'])
        hdst = " to   " + str(self['Destin'])
        rdst = " from " + str(self['Destin'])
        dprt = " port    " + str(self['dport'])
        rprt = " port    " + str(self['dport']) # answers come from this port
        prot = " proto " + str(self['Protocol'])
        if self['insec']:
            spo = " --sport 0: "
            rpo = " --dport 0: "
        else:
            spo = " --sport " + str(self['sport'])
            rpo = " --dport " + str(self['sport'])
        if icmp_type:
            spo = ""
            rpo = ""
            rprt = ""
            dprt = " --icmpv6-type " + str(self['dport'])
        #ip6 has no states!
        if proto in ['ip6']:
            prot = ""
            spo = ""
            rpo = ""
            dprt = ""
            rprt = ""
            st_new = ""
            st_ans = ""
        #line1 = hsrc + hdst + prot + spo + dprt + st_new + act
        #line2 = rsrc + rdst + prot + rpo + rprt + st_ans + act
        line1 = act + u" in quick " + hsrc + hdst + dprt + prot + st_new
        line2 = act + u"out quick " + rsrc + rdst +        prot + st_ans
        #
        comm = u""
        if commented:
            comm = u"#"
        ipi = comm #+ "/sbin/ip6tables -A   input___new "
        ipo = comm #+ "/sbin/ip6tables -A   output__new "
        ipf = comm #+ "/sbin/ip6tables -A   forward_new "
        if not self['System-Forward'] and self['travers']:
            self.msg = "# System should not forward by configuration"
            return
        if self['travers']:
            self.msg = "# System should not forward until redesigned"
            return
        if self['travers'] or self['i_am_s'] or self['i_am_d']:
            if self['noif']:
                sif = ""
                dif = ""
            else:
                sif = ""# -i "+ str(self['destin-if'])
                dif = ""# -o "+ str(self['destin-if'])
            if self['dst-linklocal']:
                self.msg = "# dst-linklocal ==> no rule generated"
                return
            print ipo + dif + line1
            outfile.write(ipo + dif + line1 + u'\n')
            if answer_packets:
                print ipi + sif + line2
                outfile.write(ipi + sif + line2 + u'\n')
        self.msg = "# WXP-SP3  n o t   y e t  r e a d y !"
        return

    def produce_IPF(self, outfile, commented):
        """
        do one pair out of a rule for Free-, Net-BSD, OpenSolaris
        """
        #print u"# producing ipf commands for rule:", self['Rule-Nr'],
        #print u"Pair: ", self['Pair-Nr']
        #print u"# n o t   y e t   r e a d y"
        self.msg = "# IPF is n o t  y e t   i m p l e m e n t e d !"
        return


class IP6_Filter():
    """
    Devicetype mostly independant Filter
    """
    os = 'Unknown'
    me = None

    def __init__(self, debuglevel, path, name, os, fwd, asym, interfaces=None):
        """start with an empty filter"""
        self.rules = []
        self.debuglevel = debuglevel
        self.path = path
        self.name = name
        self.forward = fwd
        self.asymmetric = asym
        self.msg = ""
        if 'Debian' in os:
            self.os = 'Debian'
        elif 'OpenBSD' in os:
            self.os = 'OpenBSD'
        elif 'OpenSolaris' in os:
            self.os = 'OpenSolaris'
        elif 'Win-XP-SP3' in os:
            self.os = 'Win-XP-SP3'
        else:
            self.os = "Unknown operating system for host: %s" % (name)
            print "# try to create filter object for unknown OS",
            print self.name, self.path, self.os
        return

    def append(self, rule):
        """
        append another rule to the end of the creation list
        """
        self.rules.append(rule)

    def mangle_file(self, outfile, mangleinclude):
        """
        include a file into the outputfile, paketmangling or whatever
        """
        self.msg = ""
        mangle_filename = self.path + u'/' + mangleinclude
        try:
            mang = open(mangle_filename)
            self.msg = "# start reading mangle-file: %s" % (mangle_filename)
            print "# mangle-file: %s inclusion starts" % mangle_filename
            outfile.write("# mangle-file: %s inclusion starts\n" % mangle_filename)
            for line in mang:
                print line,
                outfile.write(line)
            mang.close()
            print "# mangle-file: %s inclusion successfully ended" % mangle_filename
            outfile.write("# mangle-file: %s inclusion successfully ended\n" % mangle_filename)
        except:
            self.msg = "# failed reading mangle-file: %s, but OK" % (mangle_filename)
            print "# mangle-file: %s not found, no problem\n" % mangle_filename
            outfile.write("# mangle-file: %s not found, no problem\n" % mangle_filename)

    def mach_output(self, fname=None):
        """
        construct header, rules and footer altogether
        """
        if fname == None:
            fname = self.path + '/output'
        header_file = self.path + "/../../etc/" + str(self.os) + "-header"
        footer_file = self.path + "/../../etc/" + str(self.os) + "-footer"
        outfile = open(fname, 'w')
        head = open(header_file, 'r')
        header_name = u"%-25s" %(self.name)
        date = time.localtime()
        header_date = time.strftime("%Y-%m-%d %H:%M")
        # beautify header, device-name, date,
        for line in head:
            l = line.replace('cccccc                   ', header_name)
            line = l.replace('dddddd          ', header_date)
            outfile.write(line)
        head.close()
        # read mangle-start if present
        self.mangle_file(outfile,u'mangle-startup')
        #outfile.write(u'echo -n "##      ."; ')
        # every rule could do an output now
        for rule in self.rules:
            self.final_this_rule(rule, outfile)
        # some finalization, get ready
        outfile.write(u'echo "." ')
        # read mangle-end if present
        self.mangle_file(outfile,u'mangle-endup')
        foot = open(footer_file, 'r')
        outfile.writelines(foot.readlines())
        outfile.close()
        return

    def final_this_rule(self, rule, outfile):
        """
        do output for one pair out of rule-nr into file: outfile,
        convert simple list-structure in rule into Rule-UserDict-Object
        """
        r = Ip6_Filter_Rule()
        r['debuglevel'] = self.debuglevel
        r['Output'] = outfile
        r['OS'] = self.os
        r['System-Name'] = self.name.strip()
        r['Asymmetric'] = self.asymmetric
        r['RuleText'] = rule.pop(0)         # Orig. Rule Text as List (clone)
        r['System-Forward'] = rule.pop(0)   # 2
        r['Rule-Nr'] = rule.pop(0)          # 3
        r['Pair-Nr'] = rule.pop(0)          # 4
        r['i_am_s'] = rule.pop(0)           # 5
        r['i_am_d'] = rule.pop(0)           # 6
        r['Source'] = rule.pop(0)           # 7
        r['Destin'] = rule.pop(0)           # 8
        r['source-if'] = rule.pop(0)        # 9
        r['source-rn'] = rule.pop(0)        #10
        r['destin-if'] = rule.pop(0)        #11
        r['destin-rn'] = rule.pop(0)        #12
        r['Protocol'] = rule.pop(0)         #13
        r['dport'] = rule.pop(0)            #14
        r['Action'] = rule.pop(0)           #15
        if 'NOIF' in rule[-1]:
            r['noif'] = True
        if 'NONEW' in rule[-1]:
            r['nonew'] = True
        if 'NOSTATE' in rule[-1]:
            r['nostate'] = True
        if 'INSEC' in rule[-1]:
            r['insec'] = True
        if self.asymmetric:
            r['nostate'] = True
        r['src-multicast'] = r['Source'].is_multicast
        r['src-linklocal'] = r['Source'].is_link_local
        r['dst-multicast'] = r['Destin'].is_multicast
        r['dst-linklocal'] = r['Destin'].is_link_local
        if r['source-rn'] <> r['destin-rn']:
            r['travers'] = True
        if r['source-if'] <> r['destin-if']:
            r['travers'] = True
        # source or destin doesn't do forwarding except FORCED
        if r['i_am_s']:
            r['travers'] = False
        if r['i_am_d']:
            r['travers'] = False
        # option FORCED overrides some calculations
        if 'FORCED' in rule[-1]:
            r['i_am_s'] = True
            r['i_am_d'] = True
            r['travers'] = True
        s = "# "+'-'*76 + " #"
        self.msg = s + '\n'
        outfile.write(s+'\n')
        self.msg += str(r)
        #print "%s" % (r),
        print self.msg
        outfile.write(str(r))
        #use r.produce and later r.__del__(automagically)
        r.produce(outfile)
        #print s
        #outfile.write(s)
