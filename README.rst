Obligate
===========
Migrates the Melange database to Quark.

System Requirements
===================
Obligate will hang indefinitely on any flavor with less than 2GB of ram, so you should upgrade your flavor if this is the case.

Install
============
Have the following installed:

sudo apt-get install mysql-server build-essential git-core libmysqlclient-dev python-dev python-pip

pip install virtualenv tox


Now you can run the install script included in this repo:
    ``./install.sh``
    
*IMPORTANT:*
Set the database root username and password in ".config"

Usage
=====
    ``tox -e py27``


If all goes well you should see a green "Congratulations :)". 
If you don't, contact: john.perkins@rackspace.com xor justin.hammond@rackspace.com xor jason.meridth@rackspace.com
