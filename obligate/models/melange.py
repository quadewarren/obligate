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
import ConfigParser as cfgp
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

basepath = os.path.dirname(os.path.realpath(__file__))
basepath = os.path.abspath(os.path.join(basepath, os.pardir))

config = cfgp.ConfigParser()
config_file_path = "{}/../.config".format(basepath)
config.read(config_file_path)

username = config.get('source_db', 'user', 'changeuserinconfig')
password = config.get('source_db', 'password', 'changepasswordinconfig')
location = config.get('source_db', 'location', 'changelocationinconfig')
dbname = config.get('source_db', 'dbname', 'changetablenameinconfig')

engine = create_engine("mysql://{}:{}@{}/{}".
                       format(username, password, location, dbname),
                       echo=False)

Base = declarative_base(engine)


class MelangeMixin(object):
    """"""
    __table_args__ = {'autoload': True}


class Interfaces(MelangeMixin, Base):
    """"""
    __tablename__ = "interfaces"


class AllocatableIPs(MelangeMixin, Base):
    """"""
    __tablename__ = "allocatable_ips"


class AllocatableMacs(MelangeMixin, Base):
    """"""
    __tablename__ = "allocatable_macs"


class AllowedIps(MelangeMixin, Base):
    """"""
    __tablename__ = "allowed_ips"


class IpAddresses(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_addresses"


class IpBlocks(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_blocks"


class IpNats(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_nats"


class IpOctets(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_octets"


class IpRanges(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_ranges"


class IpRoutes(MelangeMixin, Base):
    """"""
    __tablename__ = "ip_routes"


class MacAddressRanges(MelangeMixin, Base):
    """"""
    __tablename__ = "mac_address_ranges"


class MacAddresses(MelangeMixin, Base):
    """"""
    __tablename__ = "mac_addresses"


class MigrationVersion(MelangeMixin, Base):
    """"""
    __tablename__ = "migrate_version"


class Policies(MelangeMixin, Base):
    """"""
    __tablename__ = "policies"
