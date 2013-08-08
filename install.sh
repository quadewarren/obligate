#!/bin/bash

chex() {
    RET=$1
    if [ $RET -ne 0 ]; then
        echo "FAIL: $2"
        exit 1
    fi
}

setup_aliases() {
    echo "alias nosetests='nosetests --logging-config=tests/logging.conf'" >> .venv/bin/activate
    alias deactivate='unalias nosetests && deactivate && unalias deactivate'
}

install_virtual_environment() {
    virtualenv --prompt='(obligate)' --distribute --no-site-packages .venv
    chex $? "Error creating virtual environment"
    setup_aliases
    source .venv/bin/activate
}

setup_lib_directory() {
    mkdir lib
}

get_neutron() {
    cd lib
    git clone https://github.com/openstack/neutron.git
    chex $? "Error cloning neutron Git repository"
    cd neutron
    python setup.py develop
    chex $? "Error running neutron setup.py"
    cd ../..
}

get_quark() {
    cd lib
    git clone https://github.com/jkoelker/quark.git
    chex $? "Error cloning quark Git repository"
    cd quark
    python setup.py develop
    chex $? "Error running quark setup.py"
    cd ../..
}

pip_install() {
   pip install -r pip-requirements.txt -r test-requirements.txt
   chex $? "Error running pip install"
}


install_virtual_environment
setup_lib_directory
get_neutron
get_quark
pip_install
echo 'Obligate installed ok.'
