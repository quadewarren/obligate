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

"""
Test the obligate migration: melange -> quark
"""

import unittest2

from obligate.models import melange
from obligate import obligate
from quark.db import models as quarkmodels
from sqlalchemy.orm import sessionmaker

def loadSession():
    Session = sessionmaker(bind=melange.engine)
    session = Session()
    return session

def flush_db():
    quarkmodels.BASEV2.metadata.drop_all(melange.engine)
    quarkmodels.BASEV2.metadata.create_all(melange.engine)


class TestMigration(unittest2.TestCase):
    def setUp(self):
        self.session = loadSession()
        flush_db()

    def tearDown(self):
        pass

    def count_items(self):
        self._get_current_melange_objects()
        self._get_new_quark_objects()
    
    def test_migration(self):
        migration = obligate.Obligator(self.session)
        migration.flush_db()
        migration.migrate()
        self._validate_migration()
        print "MIGRATION COMPLETE"

    def _validate_migration(self):
        print "validating migration"
        self._validate_ip_blocks_to_networks()
    
    def _validate_ip_blocks_to_networks(self):
        blocks = self.session.query(melange.IpBlocks).all()
        print "# of ip blocks in melange: %s" % len(blocks)
        networks = self.session.query(quarkmodels.Network).all()
        print "# of networks in quark: %s" % len(networks)
        for block in blocks:
            if block.network_id not in networks:
                print "Not in quark networks: %s" % block.network_id
        self.assertFalse(True)

    def _get_current_melange_objects(self):
        blocks = self.session.query(melange.IpBlocks).all()
        print "# of ip blocks in melange: %s" % len(blocks)
        routes = self.session.query(melange.IpRoutes).all()
        print "# of routes in melange: %s" % len(routes)
        addresses = self.session.query(melange.IpAddresses).all()
        print "# of ip addresses in melange: %s" % len(addresses)
        interfaces = self.session.query(melange.Interfaces).all()
        print "# of ip interfaces in melange: %s" % len(interfaces)
        allocatabl_ips = self.session.query(melange.AllocatableIPs).all()
        print "# of allocatable ip addresses in melange: %s" % len(allocatabl_ips)
        mac_range = self.session.query(melange.MacAddressRanges).all()
        print "# of mac address ranges in melange: %s" % len(mac_range)
         

    def _get_new_quark_objects(self):
        networks = self.session.query(quarkmodels.Network).all()
        print "# of networks in quark: %s" % len(networks)
        subnets = self.session.query(quarkmodels.Subnet).all()
        print "# of subnets in quark: %s" % len(subnets)
        routes = self.session.query(quarkmodels.Route).all()
        print "# of routes in quark: %s" % len(routes)
        addresses = self.session.query(quarkmodels.IPAddress).all()
        print "# of IP Addresses in quark: %s" % len(addresses)
        ports = self.session.query(quarkmodels.Port).all()
        print "# of ports in quark: %s" % len(ports)
        mac_range = self.session.query(quarkmodels.MacAddressRange).all()
        print "# of mac ranges in quark: %s" % len(mac_range)
        assert False
        
