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
import glob
import json
import logging as log
import unittest2

from obligate.models import melange
from obligate.utils import logit, loadSession
# from obligate import obligate
from quark.db import models as quarkmodels
from sqlalchemy import distinct, func  # noqa


class TestMigration(unittest2.TestCase):
    def setUp(self):
        self.session = loadSession()
        self.json_data = None
        logit()

    def get_scalar(self, pk_name, is_distinct=False):
        if is_distinct:
            return self.session.query(func.count(distinct(pk_name))).scalar()
        return self.session.query(func.count(pk_name)).scalar()

    def count_not_migrated(self, tablename):
        err_count = 0
        if self.json_data:
            for k, v in self.json_data[tablename]["ids"].items():
                if not v["migrated"]:
                    err_count += 1
        return err_count

    def test_migration(self):
        files = glob.glob('logs/obligate.*.json')
        log.info("files[0] == {}".format(files[0]))
        if files and len(files) > 0:
            log.debug("JSON file exists: {}".format(files[0]))
            data = open(files[0])
            self.json_data = json.load(data)
        #else:
        #    log.debug("JSON file does not exist, re-running migration")
        #    migration = obligate.Obligator(self.session)
        #    migration.flush_db()
        #    migration.migrate()
        #    log.debug("MIGRATION COMPLETE")
        #    migration.dump_json()
        self._validate_migration()
        self.assertFalse(True)

    def _validate_migration(self):
        #self._validate_ip_blocks_to_networks()
        #self._validate_ip_blocks_to_subnets()
        #self._validate_routes_to_routes()
        #self._validate_ip_addresses_to_ip_addresses()
        #self._validate_interfaces_to_ports()
        self._validate_mac_addresses_to_mac_addresses()

    def _validate_ip_blocks_to_networks(self):
        # get_scalar(column, True) <- True == "disctinct" modifier
        blocks_count = self.get_scalar(melange.IpBlocks.network_id, True)
        networks_count = self.get_scalar(quarkmodels.Network.id)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Networks", networks_count)

    def _validate_ip_blocks_to_subnets(self):
        blocks_count = self.get_scalar(melange.IpBlocks)
        subnets_count = self.get_scalar(quarkmodels.Subnet)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Subnets", subnets_count)

    def _validate_routes_to_routes(self):
        routes = self.get_scalar(melange.IpRoutes.id)
        qroutes = self.get_scalar(quarkmodels.Route.id)
        err_count = self.count_not_migrated("routes")
        self._compare_after_migration("Routes", routes - err_count,
                                      "Routes", qroutes)

    def _validate_ip_addresses_to_ip_addresses(self):
        addresses_count = self.get_scalar(melange.IpAddresses)
        qaddresses_count = self.get_scalar(quarkmodels.IPAddress)
        self._compare_after_migration("IP Addresses", addresses_count,
                                      "IP Addresses", qaddresses_count)

    def _validate_interfaces_to_ports(self):
        interfaces_count = self.get_scalar(melange.Interfaces.id)
        ports_count = self.get_scalar(quarkmodels.Port.id)
        err_count = self.count_not_migrated("interfaces")
        self._compare_after_migration("Interfaces",
                                      interfaces_count - err_count,
                                      "Ports", ports_count)

    def _validate_mac_addresses_to_mac_addresses(self):
        mac_ranges_count = self.get_scalar(melange.MacAddressRanges)
        qmac_ranges_count = self.get_scalar(quarkmodels.MacAddressRange)
        err_count = self.count_not_migrated("mac_ranges")
        self._compare_after_migration("MAC ranges", 
                                      mac_ranges_count - err_count,
                                      "MAC ranges", qmac_ranges_count)
        # validate cidr, first_address, last_address in a quark mac
        # mac address after it is migrated from a a melange mac_range.cidr
        mac_range = self.session.query(melange.MacAddressRanges).first()
        q_range = self.session.query(quarkmodels.MacAddressRange).\
            filter(quarkmodels.MacAddressRange.id == mac_range.id).first()
        self.assertEqual(q_range.cidr, 'blah')
        self.assertEqual(q_range.first_address, 'blah')
        self.assertEqual(q_range.last_address, 'blah')

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
