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

*IMPORTANT:*
Set the database root username, password, location and database name in ".config" for both the source and destination. 

Now you can run the install script included in this repo:
    ``./install.sh``
    
Usage
=====
    ``tox -e py27``


If all goes well you should see a green "Congratulations :)". If you don't, contact: john.perkins@rackspace.com xor justin.hammond@rackspace.com xor jason.meridth@rackspace.com

When a host has been migrated, move the logfiles to an archive directory. If logfiles exist, only the validation tests will execute.

Please note that the verification step only checks the first item of each table for speed sake. It is possible that some data is broken during the migration.
