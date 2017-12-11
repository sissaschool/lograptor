============
Installation
============

***********************
Installing from package
***********************

Lograptor is packaged with Python's *wheel* format on PyPI (RPM/DEB packages formats are
not maintained anymore) so you can install it using *pip*.
If your have root access you can do a system wide installation::

    sudo pip install lograptor

In this case the sources are installed under Python's packages directory
(eg. */usr/lib/python3.6/site-packages/*) and the data files (man, docs and configuration files)
are installed under standard POSIX paths (*/usr/share* and */etc*).

For an installation at user level run::

    pip install --user lograptor

In this case the files are written into `~/.local/` directory.

You can also install the package into a virtual environment (using *virtualenv* or *pyvenv*).
In this case the configuration file have to be referenced explicitly, using *--conf* option,
or the configuration files have to be copied to one of the program's default locations, that
are in order::

    ./lograptor.conf
    ~/.config/lograptor/lograptor.conf
    ~/.local/etc/lograptor/lograptor.conf
    /etc/lograptor/lograptor.conf


**********************
Installing from source
**********************

For installing from the source you also need `Python's setuptools <https://github.com/pypa/setuptools>`_,
that is generically available on almost all Linux distributions or however is packaged on PyPI.

With *setuptools* installed clone the git repository, choosing one of those commands::

  git clone https://github.com/brunato/lograptor
  git clone git://github.com/brunato/lograptor.git

or download the zip archive from the site and extract the content to a folder.
Then go into the lograptor's source base directory and type::

  python setup.py install

To install also the configuration and documentation files run::

  python setup.py install_data
