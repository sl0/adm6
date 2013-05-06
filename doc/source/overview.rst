===============
adm6 - overview
===============

.. image:: adm6-logo.png
   :width: 250px
   :align: right
   :alt: adm6 logo



*You are encouraged* to take a close look into any files 
**before** executing them.

adm6 -- prerequisites
=====================

There are only few: 
   - python, version 2.7 works, others aren't tested, but should fit as well
   - python-ipaddr, a module for IPv6-calculations made by google(TM)
   - knowledge about IPv6 isn't a must, but helpful
   - GNU make can help for your convienience

adm6 -- how to get it
=====================

Thats very simple on your commandline:
::

   ~ $ mkdir sources
   ~ $ git clone https://github.com/sl0/adm6.git
   ~ $ cd ~/sources/adm6 
   ~ $ ls 
   adm6
   demo.py
   doc
   LICENSE.txt
   Makefile
   README.rst
   reference-hostnet
   reference-hostnet-append
   tests
   ~ $

adm6 - the testbed
==================

**demo.py** contains all the neccessary stuff to setup the testbed from scratch. Just type:

``python demo.py``   

**or**     

``make new``

Anyhow, this will create a file and a directory in your home-directory:

#. configuration file: ~/.adm6.conf
#. configuration directory ~/adm6

``make clean`` will remove these

Have a look into the configuration file. Comments are included for better 
understanding. Most important: The global section contains a list of the 
devicenames. For every specific device, there is a section, wherein the 
belonging vars are captured. Within the configuration directory, there a 
directory tree is created like this:

adm6 - structure
================

+--------------------------------------+---------------------------------------------------+
|  **Path**              | **Content**                                                     |
+======================================+===================================================+
| ``~/.adm6.conf``                     | adm6 global application configuration file        |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6``                           | subdirectories etc, desc                          |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/etc``                       | configurations subdirectory                       |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/etc/Debian-header``         | Debian headerfile (start of generated output)     |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/etc/Debian-footer``         | Debian footerfile (tail of generated output)      |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/etc/hostnet6``              | common hostnet6 (hosts and networks definitions)  |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/etc``                       | 00-rules.admin (example rulefile)                 |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc``                      | one subdirecory per filterdevice                  |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/r-ex``                 | subdirecory for filterdevice r-ex                 |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/r-ex/interfaces``      | r-ex interfaces configuration                     |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/r-ex/routes``          | r-ex routing configuration                        |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/r-ex/00-rules-admin``  | r-ex administrative rules, ssh-access et.al.      |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/r-ex/10-rules-router`` | r-ex addtional rules in numbered rules-file       |
+--------------------------------------+---------------------------------------------------+
| ``~/adm6/desc/adm6``                 | subdirecory for filterdevice adm6                 |
+--------------------------------------+---------------------------------------------------+


adm6 - the picture
==================

All internet traffic is going through or coming out of the ISP router.

**All** others do! Think of the networks as connected only via r-ex as a router. 
More details are handled in the `configuration <config.html>`_ section 

.. nwdiag::

   diagram {
       inet6 -- ISP;
       inet6 [shape = cloud, color = "#e0e0e0", address ="2001:db8:1::1"];
    network extern {
       address = "2001:db8:1::/64"
       ISP  [address = "2001:db8:1::1"];
       r-ex [address = "2001:db8:1::4711"];
       www  [address = "2001:db8:1::80"];
       ns   [address = "2001:db8:1::53"];
    }
    network intern {
       address = "2001:db8:2::/64"
       r-ex    [label = "r-ex", description = "router", address = "2001:db8:2::1"];
       adm6    [description = "Admin", address = "2001:db8:2::23:23"];
       user1   [description = "User", address = "2001:db8:2::1"];
       user2   [description = "User", address = "2001:db8:2::2"];
    }
  }

adm6 - hostnet6
===============


+-------------------+-------------------------------------------+--------------------------------+
| Name              |  Address  (CIDR always)                   | # Comment                      |
+===================+===========================================+================================+
| ``adm6``          | ``2001:db8:2::23:23/128``                 | ``# administrators residence`` |
+-------------------+-------------------------------------------+--------------------------------+
| ``r-ex``          | ``2001:db8:2::1/128``                     | ``# router internal``          |
+-------------------+-------------------------------------------+--------------------------------+
| ``intern``        | ``2001:db8:2::/64``                       | ``# internal net``             |
+-------------------+-------------------------------------------+--------------------------------+
| ``users``         | ``2001:db8:2::5/128``                     | ``# internal user``            |
+-------------------+-------------------------------------------+--------------------------------+
| ``users``         | ``2001:db8:2::8/128``                     | ``# internal user``            |
+-------------------+-------------------------------------------+--------------------------------+
| ``r-ex``          | ``2001:db8:1::4711/128``                  | ``# router external``          |
+-------------------+-------------------------------------------+--------------------------------+
| ``ns``            | ``2001:db8:1::53/128``                    | ``# dns + mailserver``         |
+-------------------+-------------------------------------------+--------------------------------+
| ``www``           | ``2001:db8:1::80/128``                    | ``# webserver``                |
+-------------------+-------------------------------------------+--------------------------------+
| ``extern``        | ``2001:db8:1::/64``                       | ``# external net``             |
+-------------------+-------------------------------------------+--------------------------------+
| ``ISP``           | ``2001:db8:1::1/128``                     | ``# ISP router to inet6``      |
+-------------------+-------------------------------------------+--------------------------------+
| ``many``          | ``2000::/3``                              | ``# routed IPv6 universe``     |
+-------------------+-------------------------------------------+--------------------------------+

Take these definitions as examples. They may be used within the following rules. 
Except `users` they are all simple host definitions, `users` occurs twice and so 
defines a group. A rule referencing `users` defined like this will produce filter 
comands for each member, surprisingly.


adm6 - rules-files
==================


A single rule defines allowed or denied traffic, f.e.: 
A tcp sesion from host A to tcp port 25 on host B is allowed. 
Rules use the definitions from th hostnet6 file and are 
grouped in rules-files. 

The software is searching the rules-files in the machine 
specific directories, and they are only used for that 
machine, where it was found in it's directory.

The rules-files are searched by the pattern ``[0-9][0-9]-rules.*``, 
so multiple rules-files are possible fore each machine. 
``00-rules.admin`` should be present, one of the basic ideas is to 
have a common ruleset for all filtering devices. The sequence order how 
the multiple rules-files for every machine are read and envaluated, is 
fixd by the leading numbers. Within each rules-file, the rules are read line by 
line, commentlines are marked by a leading "#". Let's look at an example 
rules-file, f.e. 00-rules.admin:

.. tabularcolumns |R|L|L|p{5cm}|L|


+-----------+-------------+---------+---------+------------+-----------------+----------+
| #source   | destin      | proto   | port    | action     | options         | #comment |
+===========+=============+=========+=========+============+=================+==========+
| ``admin`` | ``obi-wan`` | ``tcp`` |  ``22`` | ``accept`` | ``NONE``        | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``admin`` | ``ns``      | ``tcp`` |  ``22`` | ``accept`` | ``NONE``        | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``admin`` | ``r-ex``    | ``tcp`` |  ``22`` | ``accept`` | ``NOIF``        | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``any``   | ``ns``      | ``udp`` |  ``53`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``users`` | ``ns``      | ``udp`` |  ``53`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``users`` | ``www``     | ``tcp`` |  ``25`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``users`` | ``www``     | ``tcp`` | ``143`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``users`` | ``www``     | ``tcp`` |  ``80`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+
| ``users`` | ``www``     | ``tcp`` | ``443`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+


adm6 - one rule
===============

To evaluate one rule, source and destination adresses are looked up in hostnet6 table.
As both may be groups with multiple members, Pairs are build for each relation. Lets
have an example.

Example:

+-----------+-------------+---------+---------+------------+-----------------+----------+
| #source   | destin      | proto   | port    | action     | options         | #comment |
+===========+=============+=========+=========+============+=================+==========+
| ``users`` | ``www``     | ``tcp`` |  ``80`` | ``accept`` | ``NOSTATE``     | ``#``    |
+-----------+-------------+---------+---------+------------+-----------------+----------+


corresponding hostnet5 entries:

+-------------------+-------------------------------------------+----------------------------+
| Name              |  Address  (CIDR always)                   | #comment                   |
+===================+===========================================+============================+
| ``users``         | ``2001:db8:2::5/128``                     | ``# internal user``        |
+-------------------+-------------------------------------------+----------------------------+
| ``users``         | ``2001:db8:2::8/128``                     | ``# internal user``        |
+-------------------+-------------------------------------------+----------------------------+
| ``www``           | ``2001:db8:1::80/128``                    | ``# webserver``            |
+-------------------+-------------------------------------------+----------------------------+


Expanding source and destination items of this rule results in two lists:

``source = [ '2001:db8:2::5/128', '2001:db8:2::8/128', ]``

``destin = [ '2001:db8:1::80/128', ]``

So we have two pairs of source/destinations:

1. ``2001:db8:2::5/128 ==> 2001:db8:1::80/128``

2. ``2001:db8:2::8/128 ==> 2001:db8:1::80/128``

From these, some ip6tables-statements are produced for each pair for each participating machine.

+--------------------------------------------------------------------------------------------------------------+
|   machine:        **www**                                                                                    |
+==============================================================================================================+
| ``ip6tables -A INPUT -i eth0 -s 2001:db8:2::5/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``        |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A OUTPUT -o eth0 -d 2001:db8:2::5/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``       |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A INPUT -i eth0 -s 2001:db8:2::8/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``        |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A OUTPUT -o eth0 -d 2001:db8:2::8/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``       |
+--------------------------------------------------------------------------------------------------------------+


+--------------------------------------------------------------------------------------------------------------+
|   machine:        **r-ex**                                                                                   |
+==============================================================================================================+
| ``ip6tables -A FORWARD -i eth2 -s 2001:db8:2::5/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``      |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A FORWARD -i eth1 -d 2001:db8:2::5/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``      |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A FORWARD -i eth2 -s 2001:db8:2::8/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``      |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A FORWARD -i eth1 -d 2001:db8:2::8/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``      |
+--------------------------------------------------------------------------------------------------------------+


+--------------------------------------------------------------------------------------------------------------+
|   machine:        **user1**                                                                                  |
+==============================================================================================================+
| ``ip6tables -A OUTPUT -i eth0 -s 2001:db8:2::5/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``       |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A INPUT -o eth0 -d 2001:db8:2::5/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``        |
+--------------------------------------------------------------------------------------------------------------+


+--------------------------------------------------------------------------------------------------------------+
|   machine:        **user2**                                                                                  |
+==============================================================================================================+
| ``ip6tables -A OUTPUT -i eth0 -s 2001:db8:2::8/128 -d 2001:db8:1::80/128 -p tcp --dport 80 -j ACCEPT``       |
+--------------------------------------------------------------------------------------------------------------+
| ``ip6tables -A  INPUT -o eth0 -d 2001:db8:2::8/128 -s 2001:db8:1::80/128 -p tcp --sport 80 -j ACCEPT``       |
+--------------------------------------------------------------------------------------------------------------+


adm6 - production
=================

To have these different results, adm6 needs to have 
informations about interfaces and routing-tables of the machines.
These are stored in the machines directories, usually in a format, like they 
can be read on the commandline. F.e. in Linux we see:

+---------------------------------------------------------------------------------------------------+
| ip -6 route show | grep -v fe80                                                                   |
+===================================================================================================+
| ``2001:db8:1::/64 dev eth1  proto kernel  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295``  |
+---------------------------------------------------------------------------------------------------+
| ``2001:db8:2::/64 dev eth2  proto kernel  metric 256  mtu 1500 advmss 1440 hoplimit 4294967295``  |
+---------------------------------------------------------------------------------------------------+
| ``2000::/3 via 2001:db8:1::1 dev eth1  metric 1024  mtu 1500 advmss 1440 hoplimit 4294967295``    |
+---------------------------------------------------------------------------------------------------+

The Interface configuration is read by commandline tool **ifconfig**.

These informations are used for each source and destination address pair: 

1. If any of the source or destination adresses are equal to a local configured adress, 
   then sure it's incoming or outgoing traffic. If both aren't used locally, the machines 
   routingtable is looked up for the linenumbers for targeting the source and destination 
   address. If these are reachable on the same route, the traffic is not traversing the 
   filtering machine, no filtercommands are generated.
2. If source and destination addresses aren't reachable through the same route, traffic 
   probably is traversing this filtering machine. System-wide configuration allows 
   or disallows forwarding, if allowed, correspondig filtercommands are generated.

More details may be found in the sources. But it should be as simple as described here.
Now we know, how the concept works. Let's have a demonstration.


adm6 - and now?
===============

Simply tpye:

``make run``

All generated filters are written to the foreseen locations in the
machines homedir, the default filename is: ``output``. Now you should look into these files...
 
adm6 - real world
=================

Perhaps you like to add a first real world machine, add the interfaces, routing informations 
and hostnet6 definitions. Then you should create a ruleset. Perhaps, as a minimum, you like to allow a tcp/22 to you machine? Keep it simple, at least for the startup:

``make run``

Look into your created output, copy it to the target machine, look again, run it.

Thats all of the magic for now. More will come, distribution, fault checking, and the like.

Have fun!

sl0
