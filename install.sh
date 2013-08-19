#!/bin/bash

chex() {
    RET=$1
    if [ $RET -ne 0 ]; then
        echo "FAIL: $2"
        exit 1
    fi
}

install_virtual_environment() {
    virtualenv --prompt='(obligate)' --distribute --no-site-packages .venv
    chex $? "Error creating virtual environment"
}

pip_install() {
   pip install -r pip-requirements.txt -r test-requirements.txt
   chex $? "Error running pip install"
}

unset PYTHONDONTWRITEBYTECODE
install_virtual_environment
source .venv/bin/activate
pip install --upgrade pip distribute
pip_install

if [ ! -f .config ]; then
    echo '[db]' > .config
    echo 'user=root' >> .config
    echo 'password=CHANGEME' >> .config
fi

echo
echo 'Obligate installed ok.'
echo 'Important:'
echo 'Please set the database credentials in .config before proceeding.'
