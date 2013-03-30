============
adm6 - rules
============

.. image:: adm6-logo.png
   :width: 250px
   :align: right
   :alt: adm6 logo



*adm6* - rules are following the main goal of simplicity.
Transparency is a must: Keep it simple!

*adm6* - rules are constructed from few elements:

1. source name from ``hostnet6`` file
2. destination name from ``hostnet6`` file
3. protocol from ``/etc/protocols``
4. service names or numbers from ``/etc/services``
5. action explicitly choosen from ``{accept, deny, reject}``
6. optional arguments (see list bleow)
7. optional comment

Every rule needs to have at least the first five elements, it describes some kind of allowed traffic. 

*adm6* - default rule: The headerfiles are fixing any default behavior: **Deny** any traffic, which is not explicitely allowed by a rule. This is not a configuration option to prevent from misusage.

*adm6* - rule options: Source, destination, portocol, port and action are selfexplaining, so the implemented options are listed here:

+---------------------+--------------------------------------------------------------+
| ``option``          | ``meaning``                                                  |
+=====================+==============================================================+
| ``LOG``             | ``additionally log each packet, useful for debugging``       |
+---------------------+--------------------------------------------------------------+
| ``INSEC``           | ``allow sourceports lower than 1024 as well``                |
+---------------------+--------------------------------------------------------------+
| ``NOIF``            | ``suppress explicite interface for this traffic``            |
+---------------------+--------------------------------------------------------------+
| ``NONEW``           | ``allow established and related traffic only, f.e. for ftp`` |
+---------------------+--------------------------------------------------------------+
| ``NOSTATE``         | ``suppress stateful inspection for this traffic``            |
+---------------------+--------------------------------------------------------------+
| ``FORCED``          | ``force INPUT, OUTPUT and FORWARD filter statements``        |
+---------------------+--------------------------------------------------------------+

Most of these are reasoned by experience with IPv4 filtering, as they proofed to be useful.
Some other options are planned, but not yet implemented:

 +---------------------+--------------------------------------------------------------+
 | ``option``          | ``meaning``                                                  |
 +=====================+==============================================================+
 | ``UNTIL_YYYYMMDD``  | ``generates filtercommands before this date``                |
 +---------------------+--------------------------------------------------------------+
 | ``FROM_YYYYMMDD``   | ``generates filtercommands after this date``                 |
 +---------------------+--------------------------------------------------------------+
 | ``NOFORWARD``       | ``suppress generation of forwarding filtercommand``          |
 +---------------------+--------------------------------------------------------------+

