Obligate
===========
Migrates the Melange database to Quark.

Install
============
Have the following installed:

sudo apt-get install mysql-server build-essential git-core libmysqlclient-dev python-dev python-pip
pip install virtualenv tox

*IMPORTANT:*
Set the database root password in obligate/models/melange.py


Now you can run the install script included in this repo:
    ``./install.sh``

Usage
=====
    ``tox -e py27``
    

If all goes well you should see a green "Congratulations :)". 
If you don't, contact: john.perkins@rackspace.com xor justin.hammond@rackspace.com xor jason.meridth@rackspace.com
