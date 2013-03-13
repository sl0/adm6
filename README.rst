.. adm6 README, started early in 2013, still growing

=============
adm6 - README
=============

README for *adm6,* a good starting point for getting to know something about ...

License
=======

As a matter of common sense, first of all software for security should be transparent, i.e. everybody
should be able to dive into the software and perhaps may want to improve it.
So there wasn't much choice: *adm6* License is GPLv3 or newer, see LICENSE.txt.
The reason is, there shall never be hidden improvements spread in a so called
commecial version. Thanks for thinking about and understanding.

Where adm6 comes from
=====================

*adm6* intentionally was developed for getting a deeper knowledge by doing and 
a more secure IPv6 networking. First ideas came up, because there was some 
knowhow about IPv4 and howto filter these packets for better bandwith usage 
and a more secure way of communications. 
*Simple security policy editor* (http://sspe.sourceforge.net) gives an example
of a framework, which may be useful to build shell-scripts using iptables 
for many machines running linux OS. It was written in perl and shell for a 
linux driven enterprise. Main advantage is a single set of rules for 
the packetfiltering hosts alltogether.
As the concepts of sspe are working well since 2002 until now, 
adm6 applies them to IPv6 except of the IPv4 specific NAT difficulties.

How adm6 was started
====================

After a first look into the python universe and after there was a /48 delivered
on a leased line, I started to write some plain python files. One of my friends
recommended me to put them into a repository, write some explanations and to
deposit these on a public place. First choice was http://evolvis.org because of
a friendship to one of their maintainers. On some german conferences *adm6* was presented:

#. LinuxTag 2011, Berlin
#. Heise IPv6 Conference, 2011, Frankfurt
#. OpenRheinRuhr 2011, Oberhausen
#. Secure Linux Administrators Conference 2011, Berlin
#. Frühjahrsfachgespräch 2012, München

People listened, asked a few questions. So I knew my software to
be somehow strange but kept on going...

Some other small python projects came across my way ... I learned about
testing python code using nose, and now I'm conviced, every non fully 
tested software is broken by design. So I started to write tests, because 
I always wanted it to become a stable and reliable product. 
I took it file by file, wrote the tests and put the results onto my github 
profile. Here it is.

Todays adm6 status
==================

Here it's not ready. If you like the previous version, that means the ugly 
untested adm6 software, have a look at http://evolvis.org/projects/adm6
which has a german description only, sorry.

Here it is still growing, especially the tests still are in develpoment. 

Have fun!

sl0
