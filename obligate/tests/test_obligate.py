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
import datetime
import glob
import json
import logging as log
import os
import sys
import unittest2

from obligate.models import melange
from obligate.utils import logit
from obligate import obligate
from quark.db import models as quarkmodels
from sqlalchemy.orm import sessionmaker


def loadSession():
    # TODO: centralize between migration and tests
    Session = sessionmaker(bind=melange.engine)
    session = Session()
    return session


class TestMigration(unittest2.TestCase):
    def setUp(self):
        self.session = loadSession()
        self.json_data = None
        logit()

    def count_items(self):
        self._get_current_melange_objects()
        self._get_new_quark_objects()

    def test_migration(self):
        files = glob.glob('../logs/obligate.*.json')
        if files and len(files) > 0:
            log.debug("JSON file exists: {}".format(files[0]))
            data = open(files[0])
            self.json_data = json.load(data)
        else:
            log.debug("JSON file does not exist, re-running migration")
            migration = obligate.Obligator(self.session)
            migration.flush_db()
            migration.migrate()
            log.debug("MIGRATION COMPLETE")
            migration.dump_json()
        self._validate_migration()
        self.assertFalse(True)

    def _validate_migration(self):
        self._validate_ip_blocks_to_networks()
        self._validate_ip_blocks_to_subnets()
        self._validate_routes_to_routes()
        self._validate_ip_addresses_to_ip_addresses()
        self._validate_interfaces_to_ports()
        self._validate_mac_addresses_to_mac_addresses()

    def _validate_ip_blocks_to_networks(self):
        blocks = self.session.query(melange.IpBlocks).all()
        networks = self.session.query(quarkmodels.Network).all()
        self._compare_after_migration("IP Blocks", len(blocks),
                                      "Networks", len(networks))
        #ids_not_migrated = self.json_data['networks']['orphaned ids']
        #ids_migrated = self.json_data['networks']['num migrated']
        #log.debug("Number of network IDs not migrated is {}".\
        #          format(len(ids_not_migrated)))
        #log.debug("Number of network IDs migrated is {}".\
        #          format(ids_migrated))
        #log.debug(dir(blocks[0]))

    def _validate_ip_blocks_to_subnets(self):
        blocks = self.session.query(melange.IpBlocks).all()
        subnets = self.session.query(quarkmodels.Subnet).all()
        self._compare_after_migration("IP Blocks", len(blocks),
                                      "Subnets", len(subnets))

    def _validate_routes_to_routes(self):
        routes = self.session.query(melange.IpRoutes).all()
        qroutes = self.session.query(quarkmodels.Route).all()
        self._compare_after_migration("Routes", len(routes),
                                      "Routes", len(qroutes))

    def _validate_ip_addresses_to_ip_addresses(self):
        addresses = self.session.query(melange.IpAddresses).all()
        qaddresses = self.session.query(quarkmodels.IPAddress).all()
        self._compare_after_migration("IP Addresses", len(addresses),
                                      "IP Addresses", len(qaddresses))

    def _validate_interfaces_to_ports(self):
        interfaces = self.session.query(melange.Interfaces).all()
        ports = self.session.query(quarkmodels.Port).all()
        self._compare_after_migration("Interfaces", len(interfaces),
                                      "Ports", len(ports))

    def _validate_mac_addresses_to_mac_addresses(self):
        mac_ranges = self.session.query(melange.MacAddressRanges).all()
        qmac_ranges = self.session.query(quarkmodels.MacAddressRange).all()
        self._compare_after_migration("MAC ranges", len(mac_ranges),
                                      "MAC ranges", len(qmac_ranges))

    def _compare_after_migration(self, melange_type, melange_count,
                                 quark_type, quark_count):
        if melange_count != quark_count:
            log.error("The number of Melange {} ({}) does "
                      "not equal the number of Quark {} ({})".
                      format(melange_type, melange_count,
                             quark_type, quark_count))
        else:
            log.info("Melange {} successfully migrated to Quark {}. "
                     "Total count {}.".format(melange_type, quark_type,
                                              melange_count))
