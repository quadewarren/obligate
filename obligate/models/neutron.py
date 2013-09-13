# Copyright (c) 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import declarative_base
import os
import ConfigParser as cfgp

basepath = os.path.dirname(os.path.realpath(__file__))
basepath = os.path.abspath(os.path.join(basepath, os.pardir))

config = cfgp.ConfigParser()
config_file_path = "{}/../.config".format(basepath)
config.read(config_file_path)

username = config.get('destination_db', 'user', 'changeuserinconfig')
password = config.get('destination_db', 'password', 'changepasswordinconfig')
location = config.get('destination_db', 'location', 'changelocationinconfig')
tablename = config.get('destination_db', 'tablename',
                       'changetablenameinconfig')

engine = create_engine("mysql://{}:{}@{}/{}".
                       format(username, password, location, tablename),
                       echo=False)
