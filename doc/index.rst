.. lograptor documentation master file, created by
   sphinx-quickstart on Wed Aug 20 08:41:15 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

===============================================
lograptor - a command line tool for system logs
===============================================

Lograptor is a GREP-like tool which provides a command-line interface for processing system logs.

Regular expression searches can be performed together with filtering rules and scope
delimitation options. Each search run can be sent to an output channel (stdout, e-mail,
file) and can produces a customizable report.

The program can parse logs written in RFC 3164 and RFC 5424 formats. Lograptor requires
Python >= 2.7, and is provided with a base configuration for a set of well known applications.
You can easily add new applications or new rules to match other unparsed logs.

.. toctree::
   :maxdepth: 1

   lograptor
   lograptor-conf
   lograptor-apps
   lograptor-examples

