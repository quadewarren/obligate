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
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


engine = create_engine("mysql://root:password@localhost/melange", echo=True)
Base = declarative_base(engine)


class Interfaces(Base):
    """"""
    __tablename__ = "interfaces"
    __table_args__ = {'autoload': True}


class AllocatableIPs:
    """"""
    __tablename__ = "allocatable_ips"
    __table_args__ = {'autoload': True}


class AllocatableMacs:
    """"""
    __tablename__ = "allocatable_macs"
    __table_args__ = {'autoload': True}


class AllowedIps:
    """"""
    __tablename__ = "allowed_ips"
    __table_args__ = {'autoload': True}


class IpAddresses:
    """"""
    __tablename__ = "ip_address"
    __table_args__ = {'autoload': True}


class IpBlocks:
    """"""
    __tablename__ = "ip_blocks"
    __table_args__ = {'autoload': True}


class IpNats:
    """"""
    __tablename__ = "ip_nats"
    __table_args__ = {'autoload': True}


class IpOctets:
    """"""
    __tablename__ = "ip_octets"
    __table_args__ = {'autoload': True}


class IpRanges:
    """"""
    __tablename__ = "ip_ranges"
    __table_args__ = {'autoload': True}


class IpRoutes:
    """"""
    __tablename__ = "ip_routes"
    __table_args__ = {'autoload': True}


class MacAddressRanges:
    """"""
    __tablename__ = "mac_address_ranges"
    __table_args__ = {'autoload': True}


class MacAddresses:
    """"""
    __tablename__ = "mac_addresses"
    __table_args__ = {'autoload': True}


class Policies:
    """"""
    __tablename__ = "policies"
    __table_args__ = {'autoload': True}


def loadSession():
    #metadata = Base.metadata
    Session = sessionmaker(bind=engine)
    session = Session()
    return session
