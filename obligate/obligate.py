#Copyright (c) 2012 OpenStack Foundation
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
from clint.textui import colored
from clint.textui import progress
import datetime
import json
from models import melange, neutron
import netaddr
from quark.db import models as quarkmodels
import time
import traceback
from utils import logit, to_mac_range, make_offset_lengths, migrate_tables, pad
from utils import trim_br

log = logit('obligate.obligator')


class Obligator(object):
    def __init__(self, melange_sess=None, neutron_sess=None):
        self.error_free = True
        self.interface_tenant = dict()
        self.interfaces = dict()
        self.interface_network = dict()
        self.interface_ip = dict()
        self.port_cache = dict()
        self.policy_ids = dict()
        self.melange_session = melange_sess
        self.neutron_session = neutron_sess
        file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
        now = datetime.datetime.now()
        self.json_filename = 'logs/obligate.{}'\
            .format(now.strftime(file_timeformat))
        self.json_data = dict()
        self.migrate_tables = migrate_tables
        self.build_json_structure()
        if not self.melange_session:
            log.warning("No melange session created when initializing"
                        " Obligator.")

    def build_json_structure(self):
        """
        Create the self.json_data structure and populate defaults
        """
        for table in self.migrate_tables:
            self.json_data[table] = {'num migrated': 0,
                                     'ids': dict()}

    def init_id(self, tablename, id, num_exp=1):
        """
        initially set the id in the table
        Each id gets a dictionary.
        If id is migrated, it is set to true and the migration count
        increases on subsequent migrations.
        If an exception occurs at any point, a reason is populated
        Unsuccessful migrations replace the None with a reason string.
        """
        try:
            self.json_data[tablename]['ids'][id] = {'migrated': False,
                                                    'migration count': num_exp,
                                                    'reason': None}
        except Exception:
            log.error("Inserting {} on {} failed.".format(id, tablename),
                      exc_info=True)

    def migrate_id(self, tablename, id):
        try:
            self.json_data[tablename]['ids'][id]['migrated'] = True
            self.json_data[tablename]['ids'][id]['migration count'] -= 1
            self.incr_num(tablename)
        except Exception:
            log.error("Key {} not in {}".format(id, tablename))

    def incr_num(self, tablename):
        """
        Increase the json_data[tablename]['num migrated']
        This is syntactic sugar.
        """
        self.json_data[tablename]['num migrated'] += 1

    def set_reason(self, tablename, id, reason):
        try:
            self.json_data[tablename]['ids'][id]['reason'] = reason
        except Exception:
            log.error("Key {} not in {}"
                      " (tried reason {})".format(id, tablename, reason))

    def dump_json(self):
        """
        This should only be called once after self.json_data has been populated
        otherwise the same data will be written multiple times.
        """
        for tablename in progress.bar(self.migrate_tables,
                                      label=pad('dump json')):
            with open('{}.{}.json'.format(self.json_filename, tablename),
                      'wb') as fh:
                json.dump(self.json_data[tablename], fh)

    def flush_db(self):
        log.debug("drop/create imminent.")
        quarkmodels.BASEV2.metadata.drop_all(melange.engine)
        quarkmodels.BASEV2.metadata.drop_all(neutron.engine)
        log.debug("drop_all complete")
        quarkmodels.BASEV2.metadata.create_all(melange.engine)
        quarkmodels.BASEV2.metadata.create_all(neutron.engine)
        log.debug("create_all complete.")

    def do_and_time(self, label, fx, **kwargs):
        start_time = time.time()
        log.info(colored.green("start: {}".format(label)))
        try:
            fx(**kwargs)
        except Exception as e:
            self.error_free = False
            log.critical(colored.red("Error during"
                                     " {}:{}\n{}".format(label,
                                                         e.message,
                                                         traceback.format_exc())))  # noqa
        end_time = time.time()
        log.info(colored.green("end  : {}".format(label)))
        log.info(colored.blue("delta: {} = ".format(label)) + colored.white("{:.2f} seconds".format(end_time - start_time)))  # noqa
        return end_time - start_time

    def add_to_session(self, item, tablename, id):
        self.migrate_id(tablename, id)
        self.neutron_session.add(item)

    def migrate_networks(self):
        """1. Migrate the m.ip_blocks -> q.quark_networks

        Migration of ip_blocks to networks requires one take into
        consideration that blocks can have 'children' blocks. A scan of
        the melange tables shows though that this feature hasn't been
        used.

        An ip_block has a cidr which maps to a corresponding subnet
        in quark.
        """
        blocks = self.melange_session.query(melange.IpBlocks).all()
        networks = dict()
        """Create the networks using the network_id. It is assumed that
        a network can only belong to one tenant"""
        for block in progress.bar(blocks, label=pad('networks cache')):
            self.init_id('networks', trim_br(block.network_id))
            if trim_br(block.network_id) not in networks:
                networks[trim_br(block.network_id)] = {
                    "tenant_id": block.tenant_id,
                    "name": block.network_name,
                }
            elif networks[trim_br(
                    block.network_id)]["tenant_id"] != block.tenant_id:
                r = "Found different tenant on network:{0} != {1}"\
                    .format(networks[trim_br(
                        block.network_id)]["tenant_id"],
                        block.tenant_id)
                log.critical(r)
                self.set_reason('networks', trim_br(block.network_id), r)
                raise Exception
        for net in progress.bar(networks, label=pad('networks')):
            q_network = quarkmodels.Network(id=net,
                                            tenant_id=
                                            networks[net]["tenant_id"],
                                            name=networks[net]["name"])
            self.add_to_session(q_network, 'networks', net)
        blocks_without_policy = 0
        for block in progress.bar(blocks, label=pad('subnets')):
            self.init_id('subnets', block.id)
            q_subnet = quarkmodels.Subnet(id=block.id,
                                          network_id=
                                          trim_br(block.network_id),
                                          tenant_id=block.tenant_id,
                                          cidr=block.cidr)
            self.add_to_session(q_subnet, 'subnets', q_subnet.id)
            self.migrate_ips(block=block)
            self.migrate_routes(block=block)
            # caching policy_ids for use in migrate_policies
            if block.policy_id:
                if block.policy_id not in self.policy_ids.keys():
                    self.policy_ids[block.policy_id] = {}
                self.policy_ids[block.policy_id][block.id] =\
                    trim_br(block.network_id)
            else:
                log.warning("Found block without a policy: {0}"
                            .format(block.id))
                blocks_without_policy += 1
        log.info("Cached {0} policy_ids. {1} blocks found without policy."
                 .format(len(self.policy_ids), blocks_without_policy))

    def migrate_routes(self, block=None):
        routes = self.melange_session.query(melange.IpRoutes)\
            .filter_by(source_block_id=block.id).all()
        for route in routes:
            self.init_id('routes', route.id)
            q_route = quarkmodels.Route(id=route.id,
                                        cidr=route.netmask,
                                        tenant_id=block.tenant_id,
                                        gateway=route.gateway,
                                        created_at=block.created_at,
                                        subnet_id=block.id)
            self.add_to_session(q_route, 'routes', q_route.id)

    def migrate_ips(self, block=None):
        """3. Migrate m.ip_addresses -> q.quark_ip_addresses
        This migration is complicated. I believe q.subnets will need to be
        populated during this step as well. m.ip_addresses is scattered all
        over the place and it is not a 1:1 relationship between m -> q.
        Some more thought will be needed for this one.

        First we need to use m.ip_addresses to find the relationship between
        the ip_block and the m.interfaces. After figuring out that it will
        then be possible to create a q.subnet connected to the network.

        """
        addresses = self.melange_session.query(melange.IpAddresses)\
            .filter_by(ip_block_id=block.id).all()
        for address in addresses:
            self.init_id('ips', address.id)
            """Populate interface_network cache"""
            interface = address.interface_id
            if interface is not None and\
                    interface not in self.interface_network:
                self.interface_network[interface] = \
                    trim_br(block.network_id)
            if interface in self.interface_network and\
                    self.interface_network[interface] != \
                    trim_br(block.network_id):
                log.error("Found interface with different "
                          "network id: {0} != {1}"
                          .format(self.interface_network[interface],
                                  trim_br(block.network_id)))
            deallocated = False
            deallocated_at = None
            """If marked for deallocation put it into the quark ip table
            as deallocated
            """
            if address.marked_for_deallocation == 1:
                deallocated = True
                deallocated_at = address.deallocated_at

            ip_address = netaddr.IPAddress(address.address)
            q_ip = quarkmodels.IPAddress(id=address.id,
                                         created_at=address.created_at,
                                         tenant_id=block.tenant_id,
                                         network_id=
                                         trim_br(block.network_id),
                                         subnet_id=block.id,
                                         version=ip_address.version,
                                         address_readable=address.address,
                                         deallocated_at=deallocated_at,
                                         _deallocated=deallocated,
                                         address=int(ip_address.ipv6()))
            """Populate interface_ip cache"""
            if interface not in self.interface_ip:
                self.interface_ip[interface] = set()
            self.interface_ip[interface].add(q_ip)
            self.add_to_session(q_ip, 'ips', q_ip.id)

    def migrate_interfaces(self):
        interfaces = self.melange_session.query(melange.Interfaces).all()
        no_network_count = 0
        for interface in progress.bar(interfaces, label=pad('interfaces')):
            self.init_id("interfaces", interface.id)
            if interface.id not in self.interface_network:
                self.set_reason("interfaces", interface.id, "no network")
                no_network_count += 1
                continue
            network_id = self.interface_network[interface.id]
            self.interface_tenant[interface.id] = interface.tenant_id
            q_port = quarkmodels.Port(id=interface.id,
                                      device_id=interface.device_id,
                                      tenant_id=interface.tenant_id,
                                      created_at=interface.created_at,
                                      backend_key="NVP_TEMP_KEY",
                                      network_id=network_id)
            self.port_cache[interface.id] = q_port
            self.add_to_session(q_port, "interfaces", q_port.id)
        log.info("Found {0} interfaces without a network."
                 .format(str(no_network_count)))

    def associate_ips_with_ports(self):
        for port in progress.bar(self.port_cache, label=pad('ports')):
            q_port = self.port_cache[port]
            for ip in self.interface_ip[port]:
                q_port.ip_addresses.append(ip)

    def migrate_macs(self):
        """2. Migrate the m.mac_address -> q.quark_mac_addresses
        This is the next simplest but the relationship between quark_networks
        and quark_mac_addresses may be complicated to set up (if it exists)
        """
        """Only migrating the first mac_address_range from melange."""
        import netaddr
        mac_range = self.melange_session.query(
            melange.MacAddressRanges).first()
        cidr = mac_range.cidr
        self.init_id('mac_ranges', mac_range.id)
        try:
            cidr, first_address, last_address = to_mac_range(cidr)
        except ValueError as e:
            self.set_reason(mac_range.id, "mac_ranges", e.message)
            return None
        except netaddr.AddrFormatError as afe:
            self.set_reason(mac_range.id, "mac_ranges", afe.message)
            return None
        q_range = quarkmodels.MacAddressRange(id=mac_range.id,
                                              cidr=cidr,
                                              created_at=mac_range.created_at,
                                              first_address=first_address,
                                              next_auto_assign_mac=first_address,  # noqa
                                              last_address=last_address)
        self.add_to_session(q_range, 'mac_ranges', q_range.id)
        res = self.melange_session.query(melange.MacAddresses).all()
        no_network_count = 0
        for mac in progress.bar(res, label=pad('macs')):
            self.init_id('macs', mac.address)
            if mac.interface_id not in self.interface_network:
                no_network_count += 1
                r = "mac.interface_id {0} not in self.interface_network"\
                    .format(mac.interface_id)
                self.set_reason('macs', mac.address, r)
                continue
            tenant_id = self.interface_tenant[mac.interface_id]
            q_mac = quarkmodels.MacAddress(tenant_id=tenant_id,
                                           created_at=mac.created_at,
                                           mac_address_range_id=mac_range.id,
                                           address=mac.address)
            q_port = self.port_cache[mac.interface_id]
            q_port.mac_address = q_mac.address
            self.add_to_session(q_mac, 'macs', q_mac.address)
        log.info("skipped {0} mac addresses".format(str(no_network_count)))

    def _octet_to_cidr(self, octet, ipv4_compatible=False):
        """
        Convert an ip octet to a ipv6 cidr
        """
        ipnet = netaddr.IPNetwork(
            netaddr.cidr_abbrev_to_verbose(octet)).\
            ipv6(ipv4_compatible=ipv4_compatible)
        return str(ipnet.ip)

    def migrate_policies(self):
        """
        Migrate policies

        We exclude the default policies.  These are octets that are 0 or
        ip ranges that have offset 0 and length 1.
        """
        from uuid import uuid4
        octets = self.melange_session.query(melange.IpOctets).all()
        offsets = self.melange_session.query(melange.IpRanges).all()
        for policy, policy_block_ids in progress.bar(self.policy_ids.items(),
                                                     label=pad('policies')):
            policy_octets = [o.octet for o in octets if o.policy_id == policy]
            policy_rules = [(off.offset, off.length) for off in offsets
                            if off.policy_id == policy]
            policy_rules = make_offset_lengths(policy_octets, policy_rules)
            try:
                policy_name = self.melange_session.query(
                    melange.Policies.name).\
                    filter(melange.Policies.id == policy).first()[0]
            except Exception:
                policy_name = None
            for block_id in policy_block_ids.keys():
                policy_uuid = str(uuid4())
                self.init_id('policies', policy_uuid)
                q_network = self.neutron_session.query(quarkmodels.Network).\
                    filter(quarkmodels.Network.id ==
                           policy_block_ids[block_id]).first()
                q_ip_policy = quarkmodels.IPPolicy(id=policy_uuid,
                                                   tenant_id=
                                                   q_network.tenant_id,
                                                   name=policy_name)
                q_ip_policy.networks.append(q_network)
                q_subnet = self.neutron_session.query(quarkmodels.Subnet).\
                    filter(quarkmodels.Subnet.id == block_id).first()
                q_ip_policy.subnets.append(q_subnet)
                self.add_to_session(q_ip_policy, 'policies', policy_uuid)
                for rule in policy_rules:
                    offset_uuid = str(uuid4())
                    self.init_id('policy_rules', offset_uuid)
                    q_ip_policy_rule = quarkmodels.\
                        IPPolicyRange(id=offset_uuid,
                                      offset=rule[0],
                                      length=rule[1],
                                      ip_policy_id=policy_uuid)
                    self.add_to_session(q_ip_policy_rule, 'policy_rules',
                                        offset_uuid)

    def migrate_commit(self):
        """4. Commit the changes to the database"""
        self.neutron_session.commit()

    def migrate(self):
        """
        This will migrate an existing melange database to a new quark
        database. Below melange is referred to as m and quark as q.
        """
        totes = 0.0
        totes += self.do_and_time("migrate networks, "
                                  "subnets, routes, and ips",
                                  self.migrate_networks)
        totes += self.do_and_time("migrate ports",
                                  self.migrate_interfaces)
        totes += self.do_and_time("associating ips with ports",
                                  self.associate_ips_with_ports)
        totes += self.do_and_time("migrate macs and ranges",
                                  self.migrate_macs)
        totes += self.do_and_time("migrate policies",
                                  self.migrate_policies)
        totes += self.do_and_time("commit changes",
                                  self.migrate_commit)
        log.info("TOTAL: {0:.2f} seconds.".format(totes))
        log.debug(colored.yellow("Done."))
