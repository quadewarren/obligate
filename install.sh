mkvirtualenv obligate
workon obligate
mkdir lib
cd lib
git clone https://github.com/openstack/neutron.git
cd neutron
python setup.py develop
cd ..
git clone https://github.com/jkoelker/quark.git
cd quark
python setup.py develop
cd ..
pip install -r pip-requirements.txt
echo 'Obligate installed ok.'
