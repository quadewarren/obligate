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
import ConfigParser as cfgp
import glob
import json
import logging
from obligate.models import melange, neutron
from obligate import obligate
from obligate.utils import loadSession
from obligate.utils import make_offset_lengths, migrate_tables
from obligate.utils import translate_netmask, trim_br
import os
from quark.db import models as quarkmodels
from sqlalchemy import distinct, func
import unittest2


basepath = os.path.dirname(os.path.realpath(__file__))
basepath = os.path.abspath(os.path.join(basepath, os.pardir))

config = cfgp.ConfigParser()
config_file_path = "{}/../.config".format(basepath)
config.read(config_file_path)

migrate_version = config.get('system_reqs', 'dbversion', '6')


class TestMigration(unittest2.TestCase):
    def setUp(self):
        self.melange_session = loadSession(melange.engine)
        self.neutron_session = loadSession(neutron.engine)
        self.json_data = dict()
        self.log = logging.getLogger('obligate.tests')

    def get_scalar(self, pk_name, session, filter=None, is_distinct=False):
        if is_distinct:
            return session.query(func.count(distinct(pk_name))).scalar()
        elif filter:
            return session.query(func.count(pk_name)).\
                filter(filter[0]).scalar()
        else:
            return session.query(func.count(pk_name)).scalar()

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

    def get_newest_json_file(self, tablename):
        from operator import itemgetter
        import os
        files = glob.glob('logs/*{}.json'.format(tablename))
        filetimes = dict()
        for f in files:
            filetimes.update({f: os.stat(f).st_mtime})
        jsonfiles = sorted(filetimes.items(), key=itemgetter(1))
        if jsonfiles:
            most_recent = jsonfiles[-1]
            return most_recent[0]
        else:
            return None

    def check_version(self):
        current_version = self.melange_session.query(
            melange.MigrationVersion).first()
        self.assertEqual(current_version.version, int(migrate_version))

    def test_migration(self):
        self.check_version()
        for table in migrate_tables:
            file = self.get_newest_json_file(table)
            if not file:
                self.log.debug("JSON file does not exist,"
                               " for table {} re-running migration".
                               format(table))
                migration = obligate.Obligator(self.melange_session,
                                               self.neutron_session)
                migration.flush_db()
                migration.migrate()
                file = self.get_newest_json_file(table)
            self.log.info("newest json file is {}".format(file))
            data = open(file)
            self.json_data.update({table: json.load(data)})
            self._validate_migration(table)

    def _validate_migration(self, tablename):
        exec("self._validate_{}()".format(tablename))

    def _validate_networks(self):
        # get_scalar(column, True) <- True == "distinct" modifier
        blocks_count = self.get_scalar(melange.IpBlocks.network_id,
                                       self.melange_session, [], True)
        networks_count = self.get_scalar(quarkmodels.Network.id,
                                         self.neutron_session)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Networks", networks_count)
        _block = self.melange_session.query(melange.IpBlocks).first()
        _network = self.neutron_session.query(quarkmodels.Network).\
            filter(quarkmodels.Network.id == _block.network_id).first()
        self.assertEqual(trim_br(_block.network_id), _network.id)
        self.assertEqual(_block.tenant_id, _network.tenant_id)
        self.assertEqual(_block.network_name, _network.name)

    def _validate_subnets(self):
        blocks_count = self.get_scalar(melange.IpBlocks.id,
                                       self.melange_session)
        subnets_count = self.get_scalar(quarkmodels.Subnet.id,
                                        self.neutron_session)
        self._compare_after_migration("IP Blocks", blocks_count,
                                      "Subnets", subnets_count)
        _ipblock = self.melange_session.query(melange.IpBlocks).first()
        _subnet = self.neutron_session.query(quarkmodels.Subnet).\
            filter(quarkmodels.Subnet.id == _ipblock.id).first()
        self.assertEqual(_subnet.tenant_id, _ipblock.tenant_id)
        self.assertEqual(_subnet.network_id, _ipblock.network_id)
        self.assertEqual(_subnet._cidr, _ipblock.cidr)

    def _validate_routes(self):
        routes = self.get_scalar(melange.IpRoutes.id,
                                 self.melange_session)
        qroutes = self.get_scalar(quarkmodels.Route.id,
                                  self.neutron_session)
        err_count = self.count_not_migrated("routes")
        self._compare_after_migration("Routes", routes - err_count,
                                      "Routes", qroutes)
        _route = self.melange_session.query(melange.IpRoutes).first()
        _ipblock = self.melange_session.query(melange.IpBlocks).\
            filter(melange.IpBlocks.id == _route.source_block_id).first()
        _qroute = self.neutron_session.query(quarkmodels.Route).\
            filter(quarkmodels.Route.id == _route.id).first()
        self.assertEqual(_qroute.cidr,
                         translate_netmask(_route.netmask, _route.destination))
        self.assertEqual(_qroute.tenant_id, _ipblock.tenant_id)
        self.assertEqual(_qroute.gateway, _route.gateway)
        self.assertEqual(_qroute.created_at, _ipblock.created_at)
        self.assertEqual(_qroute.subnet_id, _ipblock.id)

    def _validate_ips(self):
        import netaddr
        addresses_count = self.get_scalar(melange.IpAddresses.id,
                                          self.melange_session)
        qaddresses_count = self.get_scalar(quarkmodels.IPAddress.id,
                                           self.neutron_session)
        self._compare_after_migration("IP Addresses", addresses_count,
                                      "IP Addresses", qaddresses_count)
        _ip_addr = self.melange_session.query(melange.IpAddresses).first()
        _ipblock = self.melange_session.query(melange.IpBlocks).\
            filter(melange.IpBlocks.id == _ip_addr.ip_block_id).first()
        _q_ip_addr = self.neutron_session.query(quarkmodels.IPAddress).\
            filter(quarkmodels.IPAddress.id == _ip_addr.id).first()
        _ip_address = netaddr.IPAddress(_ip_addr.address)
        self.assertEqual(_q_ip_addr.created_at, _ip_addr.created_at)
        self.assertEqual(_q_ip_addr.used_by_tenant_id,
                         _ip_addr.used_by_tenant_id)
        self.assertEqual(_q_ip_addr.network_id, trim_br(_ipblock.network_id))
        self.assertEqual(_q_ip_addr.subnet_id, _ipblock.id)
        self.assertEqual(_q_ip_addr.version, _ip_address.version)
        self.assertEqual(_q_ip_addr.address_readable, _ip_addr.address)
        self.assertTrue(_q_ip_addr.deallocated_at ==
                        None or _ip_addr.deallocated_at)
        self.assertEqual(int(_q_ip_addr.address), int(_ip_address.ipv6()))

    def _validate_interfaces(self):
        interfaces_count = self.get_scalar(melange.Interfaces.id,
                                           self.melange_session)
        ports_count = self.get_scalar(quarkmodels.Port.id,
                                      self.neutron_session)
        err_count = self.count_not_migrated("interfaces")
        self._compare_after_migration("Interfaces",
                                      interfaces_count - err_count,
                                      "Ports", ports_count)
        _interface = self.melange_session.query(melange.Interfaces).first()
        _network_query = self.melange_session.query(melange.IpBlocks).\
            join(melange.IpAddresses)
        _network_filter = _network_query.\
            filter(_interface.id == melange.IpAddresses.interface_id)
        _networks = _network_filter.all()
        _port = self.neutron_session.query(quarkmodels.Port).\
            filter(quarkmodels.Port.id == _interface.id).first()
        self.assertEqual(_port.device_id, _interface.device_id)
        self.assertEqual(_port.tenant_id, _interface.tenant_id)
        self.assertEqual(_port.created_at, _interface.created_at)
        self.assertEqual(_port.backend_key, "NVP_TEMP_KEY")
        self.assertTrue(_port.network_id in [n.network_id for n in _networks])

    def _validate_mac_ranges(self):
        mac_ranges_count = self.get_scalar(melange.MacAddressRanges.id,
                                           self.melange_session)
        qmac_ranges_count = self.get_scalar(quarkmodels.MacAddressRange.id,
                                            self.neutron_session)
        err_count = self.count_not_migrated("mac_ranges")
        self._compare_after_migration("MAC ranges",
                                      mac_ranges_count - err_count,
                                      "MAC ranges", qmac_ranges_count)
        _mac_range = self.melange_session.query(
            melange.MacAddressRanges).first()
        _q_mac_range = self.neutron_session.query(
            quarkmodels.MacAddressRange).first()
        self.assertEqual(_q_mac_range.cidr.replace(':', '').upper(),
                         _mac_range.cidr.upper())
        self.assertEqual(_q_mac_range.created_at, _mac_range.created_at)

    def _validate_macs(self):
        macs_count = self.get_scalar(melange.MacAddresses.id,
                                     self.melange_session)
        qmacs_count = self.get_scalar(quarkmodels.MacAddress.address,
                                      self.neutron_session)
        err_count = self.count_not_migrated("macs")
        self._compare_after_migration("MACs",
                                      macs_count - err_count,
                                      "MACs", qmacs_count)
        _mac_address = self.melange_session.query(melange.MacAddresses).\
            filter(melange.MacAddresses.interface_id != None).first()
        _interface = self.melange_session.query(melange.Interfaces).\
            filter(melange.Interfaces.id == _mac_address.interface_id).first()
        _q_mac_address = self.neutron_session.query(quarkmodels.MacAddress).\
            filter(quarkmodels.MacAddress.address == _mac_address.address).\
            first()
        self.assertEqual(_q_mac_address.tenant_id, _interface.tenant_id)
        self.assertEqual(_q_mac_address.created_at, _mac_address.created_at)
        self.assertEqual(_q_mac_address.address, _mac_address.address)

    def _validate_policies(self):
        blocks_count = self.get_scalar(melange.IpBlocks.id,
                                       self.melange_session,
                                       filter=[melange.IpBlocks.policy_id != None])  # noqa
        qpolicies_count = self.get_scalar(quarkmodels.IPPolicy.id,
                                          self.neutron_session)
        err_count = self.count_not_migrated("policies")
        self._compare_after_migration("IP Block Policies",
                                      blocks_count - err_count,
                                      "Policies", qpolicies_count)

    def _get_policy_offset_total(self):
        total_policy_offsets = 0
        policy_ids = {}
        blocks = self.melange_session.query(melange.IpBlocks).all()
        for block in blocks:
            if block.policy_id:
                if block.policy_id not in policy_ids.keys():
                    policy_ids[block.policy_id] = {}
                policy_ids[block.policy_id][block.id] = block.network_id
        octets = self.melange_session.query(melange.IpOctets).all()
        offsets = self.melange_session.query(melange.IpRanges).all()
        for policy, policy_block_ids in policy_ids.items():
            policy_octets = [o.octet for o in octets if o.policy_id == policy]
            policy_offsets = [(off.offset, off.length) for off in offsets
                              if off.policy_id == policy]
            policy_offsets = make_offset_lengths(policy_octets, policy_offsets)
            for block_id in policy_block_ids.keys():
                total_policy_offsets += len(policy_offsets)
        return total_policy_offsets

    def _validate_policy_rules(self):
        offsets_count = self._get_policy_offset_total()
        qpolicy_rules_count = self.get_scalar(quarkmodels.IPPolicyRange.id,
                                              self.neutron_session)
        err_count = self.count_not_migrated("policy_rules")
        self._compare_after_migration("Offsets",
                                      offsets_count - err_count,
                                      "Policy Rules", qpolicy_rules_count)
        # first block in melange with a policy
        _block = self.melange_session.query(melange.IpBlocks).\
            filter(melange.IpBlocks.policy_id != None).first()
        # policy that matches the block:
        _policy = self.melange_session.query(melange.Policies).\
            filter(melange.Policies.id == _block.policy_id).first()
        # get the policy rules
        _octets = self.melange_session.query(melange.IpOctets).\
            filter(melange.IpOctets.policy_id == _policy.id).all()
        _ranges = self.melange_session.query(melange.IpRanges).\
            filter(melange.IpRanges.policy_id == _policy.id).all()
        tmp_octets = [o.octet for o in _octets]
        tmp_ranges = [(r.offset, r.length) for r in _ranges]
        # tmp store the converted, compressed policies:
        _expected = make_offset_lengths(tmp_octets, tmp_ranges)
        #get the matching quark policies:
        _q_network = self.neutron_session.query(quarkmodels.Network).\
            filter(quarkmodels.Network.id == _block.network_id).first()
        _q_policy = self.neutron_session.query(quarkmodels.IPPolicy).\
            filter(quarkmodels.IPPolicy.tenant_id ==
                   _q_network.tenant_id).first()
        _actual = list()
        _q_policy_rules = self.neutron_session.query(
            quarkmodels.IPPolicyRange).\
            filter(quarkmodels.IPPolicyRange.ip_policy_id ==
                   _q_policy.id).all()
        for range in _q_policy_rules:
            _actual.append((range.offset, range.length))
        self.assertItemsEqual(_expected, _actual)

    def _compare_after_migration(self, melange_type, melange_count,
                                 quark_type, quark_count):
        message = "The number of Melange {} ({}) does " \
                  "not equal the number of Quark {} ({})".\
                  format(melange_type, melange_count, quark_type, quark_count)
        self.assertEqual(melange_count, quark_count, message)
