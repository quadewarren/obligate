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
import unittest2

from obligate.models import melange
from obligate.utils import logit, loadSession, make_offset_lengths
from obligate import obligate
from quark.db import models as quarkmodels
from sqlalchemy import distinct, func  # noqa


class TestMigration(unittest2.TestCase):
    def setUp(self):
        self.session = loadSession()
        self.json_data = None
        self.log = logit('obligate.tests')

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
        else:
            self.log.critical("Trying to count not migrated "
                              "but JSON doesn't exist")
        return err_count

    def get_newest_json_file(self):
        import os
        from operator import itemgetter
        files = glob.glob('logs/*.json')
        filetimes = dict()
        for f in files:
            filetimes.update({f: os.stat(f).st_mtime})
        jsonfiles = sorted(filetimes.items(), key=itemgetter(1))
        del itemgetter  # namespace housekeeping
        if jsonfiles:
            most_recent = jsonfiles[-1]
            return most_recent[0]
        else:
            return None

    def test_migration(self):
        file = self.get_newest_json_file()
        if not file:
            self.log.debug("JSON file does not exist, re-running migration")
            migration = obligate.Obligator(self.session)
            migration.flush_db()
            migration.migrate()
            migration.dump_json()
            file = self.get_newest_json_file()
        self.log.info("newest json file is {}".format(file))
        data = open(file)
        self.json_data = json.load(data)
        self._validate_migration()

    def _validate_migration(self):
        self._validate_ip_blocks_to_networks()
        self._validate_ip_blocks_to_subnets()
        self._validate_routes_to_routes()
        self._validate_ip_addresses_to_ip_addresses()
        self._validate_interfaces_to_ports()
        self._validate_mac_addresses_to_mac_addresses()
        self._validate_ip_block_policies_to_policies()
        self._validate_offsets_to_policy_rules()

    def _validate_ip_blocks_to_networks(self):
        # get_scalar(column, True) <- True == "disctinct" modifier
        blocks_count = self.get_scalar(melange.IpBlocks.network_id, True)
        networks_count = self.get_scalar(quarkmodels.Network.id)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Networks", networks_count)

    def _validate_ip_blocks_to_subnets(self):
        blocks_count = self.get_scalar(melange.IpBlocks.id)
        subnets_count = self.get_scalar(quarkmodels.Subnet.id)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Subnets", subnets_count)

    def _validate_routes_to_routes(self):
        routes = self.get_scalar(melange.IpRoutes.id)
        qroutes = self.get_scalar(quarkmodels.Route.id)
        err_count = self.count_not_migrated("routes")
        self._compare_after_migration("Routes", routes - err_count,
                                      "Routes", qroutes)

    def _validate_ip_addresses_to_ip_addresses(self):
        addresses_count = self.get_scalar(melange.IpAddresses.id)
        qaddresses_count = self.get_scalar(quarkmodels.IPAddress.id)
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
        mac_ranges_count = self.get_scalar(melange.MacAddressRanges.id)
        qmac_ranges_count = self.get_scalar(quarkmodels.MacAddressRange.id)
        err_count = self.count_not_migrated("mac_ranges")
        self._compare_after_migration("MAC ranges",
                                      mac_ranges_count - err_count,
                                      "MAC ranges", qmac_ranges_count)

    def _validate_ip_block_policies_to_policies(self):
        blocks_count = self.get_scalar(melange.IpBlocks.id)
        qpolicies_count = self.get_scalar(quarkmodels.IPPolicy.id)
        err_count = self.count_not_migrated("policies")
        self._compare_after_migration("IP Block Policies",
                                      blocks_count - err_count,
                                      "Policies", qpolicies_count)

    def _get_policy_offset_total(self):
        total_policy_offsets = 0
        policy_ids = {}
        blocks = self.session.query(melange.IpBlocks).all()
        for block in blocks:
            if block.policy_id:
                if block.policy_id not in policy_ids.keys():
                    policy_ids[block.policy_id] = {}
                policy_ids[block.policy_id][block.id] = block.network_id
        octets = self.session.query(melange.IpOctets).all()
        offsets = self.session.query(melange.IpRanges).all()
        for policy, policy_block_ids in policy_ids.items():
            policy_octets = [o.octet for o in octets if o.policy_id == policy]
            policy_offsets = [(off.offset, off.length) for off in offsets
                              if off.policy_id == policy]
            policy_offsets = make_offset_lengths(policy_octets, policy_offsets)
            for block_id in policy_block_ids.keys():
                total_policy_offsets += len(policy_offsets)
        return total_policy_offsets

    def _validate_offsets_to_policy_rules(self):
        offsets_count = self._get_policy_offset_total()
        qpolicy_rules_count = self.get_scalar(quarkmodels.IPPolicyRange.id)
        err_count = self.count_not_migrated("policy_rules")
        self._compare_after_migration("Offsets",
                                      offsets_count - err_count,
                                      "Policy Rules", qpolicy_rules_count)

    def _compare_after_migration(self, melange_type, melange_count,
                                 quark_type, quark_count):
        message = "The number of Melange {} ({}) does " \
                  "not equal the number of Quark {} ({})".\
                  format(melange_type, melange_count, quark_type, quark_count)
        self.assertEqual(melange_count, quark_count, message)
