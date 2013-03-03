====
adm6
====

This is adm6. License is GPLv3 or newer, see LICENSE.txt

   On github is starting up not as a clone, but fron scratch
   by editing the old files from evolvis.org one by one.

Main purpose is to generate a set of ip6tables-commands from
some flat ascii-files, one for definitions, one for the rules.
Some ideas for generating pf.conf or the like will come, but
are not realized for real world usage.

Starting point is hostnet6.py, which is used to read all the 
hostnet files. Every line therein is like this:

   name        ipv6-address   # comment

The tests for this file cover 100% of the code, perhaps not 
every aspects are covered, we shall see.
