====================
adm6 - configuration
====================

.. image:: adm6-logo.png
   :width: 250px
   :align: right
   :alt: adm6 logo



*adm6* - configuration uses a python module: ConfigParser. This
is following one of the python paradigms: batteries included.

*adm6* - configuration file is located here: ``~/.adm6.conf`` 
Almost everything is specified here, except target machines details 
like interface and routing configurations.
The file is divided into sections, one of them is marked like this: ``[global]``

adm6 - global configuration
---------------------------

Herein we find top most important informations about local 
*adm6* configuration, always one by one on a separate line, 
which is divided by a *=* into a left and a right part. The 
left one names the meaning of the right parts value, here 
are follinig up the examples:

+---------------------+--------------------------+--------------------------------------------+
| ``name``            | ``meaning``              | ``example value``                          |
+=====================+==========================+============================================+
| ``version``         | ``software version``     | ``0.2``                                    |
+---------------------+--------------------------+--------------------------------------------+
| ``timestamp``       | ``creation date``        | ``2013-03-30``                             |
+---------------------+--------------------------+--------------------------------------------+
| ``home``            | ``home directory``       | ``/home/sl0/adm6``                         |
+---------------------+--------------------------+--------------------------------------------+
| ``key-file``        | ``ssh public key``       | ``~/.ssh/id_rsa.pub``                      |
+---------------------+--------------------------+--------------------------------------------+
| ``devices``         | ``adm6 targets``         | ``adm6,r-ex,ns,www,obi-wan``               |
+---------------------+--------------------------+--------------------------------------------+
| ``software``        | ``supported platforms``  | ``['Debian', 'OpenBSD', ]``                |
+---------------------+--------------------------+--------------------------------------------+
| ``debuglevel``      | ``debug vebose setting`` | ``1``                                      |
+---------------------+--------------------------+--------------------------------------------+

Comments are possible on a line by itself, lead in character is **;**

adm6 - device configuration
---------------------------

Every configured device (see global section: devices) needs to have
an own section in the configuration file, named by its device-name, f.e. ``[device#r-ex]``

The name after ``device#`` needs to match exactly to one of the global sections devices string.

+---------------------+--------------------------+-----------------------------------------------+
| ``name``            | ``meaning``              | ``example value``                             |
+=====================+==========================+===============================================+
| ``desc``            | ``description``          | ``external IPv6 router via ISP to the world`` |
+---------------------+--------------------------+-----------------------------------------------+
| ``os``              | ``operating system``     | ``Debian GNU/Linux, wheezy``                  |
+---------------------+--------------------------+-----------------------------------------------+
| ``ip``              | ``devices ssh listener`` | ``2001:db8:1:2::1``                           |
+---------------------+--------------------------+-----------------------------------------------+
| ``fwd``             | ``forwarding status``    | ``1``                                         |
+---------------------+--------------------------+-----------------------------------------------+
| ``active``          | ``active status``        | ``1``                                         |
+---------------------+--------------------------+-----------------------------------------------+
| ``asymmetric``      | ``asymmetric routing``   | ``1``                                         |
+---------------------+--------------------------+-----------------------------------------------+

What do these values mean in detail?


``desc`` may be a verbose description for the target system.

``os``  should match anyhow to one of the globally configured supported platforms.

``ip``  address of the device, ssh should listen there, the configured key should give root access.

``fwd`` forwarding status, router should have a value of 1, others 0.

``active`` active status, useful to disable a configured device from adm6 filter updates. Sometimes 
the net isn't relieable, is it?

``asymmetric`` asymmetric status, some strange behaviors have impact to the
generated filters, f.e. asymetric routing needs to suppress stateful packetfilters, 
as not all packets of a flow come through the device...  
This values needs not to be present in the config section, assumed to be 0.


adm6 - configuration comments
-----------------------------

Using python the methods of ConfigParser, it's easily possible to read and write the 
configfile in a comfortable way. But be warned, if you wirte back an existing file,
all the comments are gone, and the order of your sections is unpredicable.
