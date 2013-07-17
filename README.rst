Obligate
===========
Migrates the Melange database to Quark.

Install
============
TL;DR: 
    ``git clone https://github.com/mpath/obligate.git&&cd obligate&&mkvirtualenv obligate&&workon obligate&&mkdir lib&&cd lib&&git clone https://github.com/openstack/neutron.git&&cd neutron&&python setup.py develop&&cd ..&&git clone https://github.com/jkoelker/quark.git&&cd quark&&python setup.py develop&&cd ..&&pip install -r pip-requirements.txt&&echo 'Obligate installed ok.'``

============
    
#. Clone the repo:
    ``git clone https://github.com/mpath/obligate.git && cd obligate``

#. create a .venv for obligate:
    ``mkvirtualenv obligate``

#. Activate the .venv:
    ``workon obligate``

#. install quark and neutron (as develop) inside the venv:
    ``mkdir lib && cd lib``
    
    ``git clone https://github.com/openstack/neutron.git``
    
    ``cd neutron && python setup.py develop``
    
    ``cd ..``
    
    ``git clone https://github.com/jkoelker/quark.git``
    
    ``cd quark && python setup.py develop && cd ..``

#. install the requirements:
    ``pip install -r pip-requirements.txt``

Usage
=====
    ``python obligate.py``
