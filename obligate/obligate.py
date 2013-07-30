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
import netaddr
import time
import json
import datetime
from models import melange
from quark.db import models as quarkmodels

import logging as log
# import argparse TODO


class Obligator(object):
    def __init__(self, session=None):
        self.interface_tenant = dict()
        self.interfaces = dict()
        self.interface_network = dict()
        self.interface_ip = dict()
        self.port_cache = dict()
        self.policy_ids = dict()
        self.session = session
        file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
        now = datetime.datetime.now()
        # the json data is for testing purposes and may be removed
        # in production to increase performance slightly.
        self.json_filename = 'logs/obligate.{}.json'\
            .format(now.strftime(file_timeformat))
        self.json_data = dict()
        if not self.session:
            log.warning("No session created when initializing Obligator.")

    def build_json_structure(self):
        """
        Create the self.json_data structure and populate defaults
        The 'orphaned ids': dict()s will be formatted thusly:
         'orphaned ids': {'some id': 'some reason string',
                          'another id': 'another reason string',
                          ...
                          }
        """
        migrate_tables = ('networks',
                          'subnets',
                          'routes',
                          'ips',
                          'interfaces',
                          'allocatable_ips',
                          'macs',
                          'policies')

        for table in migrate_tables:
            self.json_data[table] = {'num migrated': 0,
                                     'orphaned ids': dict()}

    def add_orphan(self, tablename, orphan_id, reason):
        """
        Add an orphaned id/reason to the appropo json_data dict
        """
        self.json_data[tablename]['orphaned ids'][orphan_id] = reason

    def incr_num(self, tablename):
        """
        Increase the json_data[tablename]['num migrated']
        This is syntactic sugar.
        """
        self.json_data[tablename]['num migrated'] += 1

    def dump_json(self):
        """
        This should only be called once after self.json_data has been populated
        otherwise the same data will be written multiple times.
        """
        with open(self.json_filename, 'wb') as fh:
            json.dump(self.json_data, fh)

    def flush_db(self):
        log.debug("drop/create imminent.")
        quarkmodels.BASEV2.metadata.drop_all(melange.engine)
        log.debug("drop_all complete")
        quarkmodels.BASEV2.metadata.create_all(melange.engine)
        log.debug("create_all complete.")

    def do_and_time(self, label, fx, **kwargs):
        start_time = time.time()
        log.info("start: {0}".format(label))
        try:
            fx(**kwargs)
        except Exception as e:
            log.critical("Error during {0}:{1}".format(label, e.message))
            raise e
        end_time = time.time()
        log.info("end  : {0}".format(label))
        log.info("delta: {0} = {1} seconds"
                 .format(label, str(end_time - start_time)))
        return end_time - start_time

    def migrate_networks(self):
        """1. Migrate the m.ip_blocks -> q.quark_networks

        Migration of ip_blocks to networks requires one take into
        consideration that blocks can have 'children' blocks. A scan of
        the melange tables shows though that this feature hasn't been
        used.

        An ip_block has a cidr which maps to a corresponding subnet
        in quark.
        """
        blocks = self.session.query(melange.IpBlocks).all()
        networks = dict()
        """Create the networks using the network_id. It is assumed that
        a network can only belong to one tenant"""
        for block in blocks:
            if block.network_id not in networks:
                networks[block.network_id] = {
                    "tenant_id": block.tenant_id,
                    "name": block.network_name,
                }
            elif networks[block.network_id]["tenant_id"] != block.tenant_id:
                self.add_orphan('networks',
                                block.network_id,
                                'Tenant differs on network')
                log.critical("Found different tenant on network:{0} != {1}"
                             .format(networks[block.network_id]["tenant_id"],
                                     block.tenant_id))
                raise Exception
        for net in networks:
            q_network = quarkmodels.Network(id=net,
                                            tenant_id=networks[net]["tenant_id"],  # noqa
                                            name=networks[net]["name"])
            self.session.add(q_network)
        blocks_without_policy = 0
        for block in blocks:
            q_subnet = quarkmodels.Subnet(id=block.id,
                                          network_id=block.network_id,
                                          cidr=block.cidr)
            self.session.add(q_subnet)
            self.migrate_ips(block=block)
            self.migrate_routes(block=block)
            # caching policy_ids for use in migrate_policies
            if block.policy_id:
                if block.policy_id not in self.policy_ids.keys():
                    self.policy_ids[block.policy_id] = list()
                self.policy_ids[block.policy_id].append(block.id)
            else:
                log.warning("Found block without a policy: {0}"
                            .format(block.id))
                blocks_without_policy += 1
        log.info("Cached {0} policy_ids. {1} blocks found without policy."
                 .format(len(self.policy_ids), blocks_without_policy))

    def migrate_routes(self, block=None):
        routes = self.session.query(melange.IpRoutes)\
            .filter_by(source_block_id=block.id).all()
        for route in routes:
            q_route = quarkmodels.Route(id=route.id,
                                        cidr=route.netmask,
                                        tenant_id=block.tenant_id,
                                        gateway=route.gateway,
                                        created_at=block.created_at,
                                        subnet_id=block.id)
            self.session.add(q_route)

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
        addresses = self.session.query(melange.IpAddresses)\
            .filter_by(ip_block_id=block.id).all()
        for address in addresses:
            """Populate interface_network cache"""
            interface = address.interface_id
            if interface is not None and\
                    interface not in self.interface_network:
                self.interface_network[interface] = block.network_id
            if interface in self.interface_network and\
                    self.interface_network[interface] != block.network_id:
                log.error("Found interface with different "
                          "network id: {0} != {1}"
                          .format(self.interface_network[interface],
                                  block.network_id))
            deallocated = False
            deallocated_at = None
            """If marked for deallocation put it into the quark ip table
            as deallocated
            """
            if address.marked_for_deallocation == 1:
                deallocated = True
                deallocated_at = address.deallocated_at

            preip = netaddr.IPAddress(address.address)
            version = preip.version
            ip = netaddr.IPAddress(address.address).ipv6()
            q_ip = quarkmodels.IPAddress(id=address.id,
                                         created_at=address.created_at,
                                         tenant_id=block.tenant_id,
                                         network_id=block.network_id,
                                         subnet_id=block.id,
                                         version=version,
                                         address_readable=address.address,
                                         deallocated_at=deallocated_at,
                                         _deallocated=deallocated,
                                         address=int(ip))
            """Populate interface_ip cache"""
            if interface not in self.interface_ip:
                self.interface_ip[interface] = set()
            self.interface_ip[interface].add(q_ip)
            self.session.add(q_ip)

    def migrate_interfaces(self):
        interfaces = self.session.query(melange.Interfaces).all()
        no_network_count = 0
        for interface in interfaces:
            if interface.id not in self.interface_network:
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
            self.session.add(q_port)
        log.info("Found {0} interfaces without a network."
                 .format(str(no_network_count)))

    def associate_ips_with_ports(self):
        for port in self.port_cache:
            q_port = self.port_cache[port]
            for ip in self.interface_ip[port]:
                q_port.ip_addresses.append(ip)

    def _to_mac_range(self, val):
        cidr_parts = val.split("/")
        prefix = cidr_parts[0]
        prefix = prefix.replace(':', '')
        prefix = prefix.replace('-', '')
        prefix_length = len(prefix)
        if prefix_length < 6 or prefix_length > 10:
            log.warning("{0} prefix_length < 6 or prefix_length > 10."
                        " (prefix_length = {1})"
                        .format(val, prefix_length))
            #raise quark_exceptions.InvalidMacAddressRange(cidr=val)

        diff = 12 - len(prefix)
        if len(cidr_parts) > 1:
            mask = int(cidr_parts[1])
        else:
            mask = 48 - diff * 4
        mask_size = 1 << (48 - mask)
        prefix = "%s%s" % (prefix, "0" * diff)
        try:
            cidr = "%s/%s" % (str(netaddr.EUI(prefix)).replace("-", ":"), mask)
        except netaddr.AddrFormatError as e:
            log.warning("{0} raised netaddr.AddrFormatError: {1}... ignoring."
                        .format(prefix, e.message))
            #raise quark_exceptions.InvalidMacAddressRange(cidr=val)
        prefix_int = int(prefix, base=16)
        return cidr, prefix_int, prefix_int + mask_size

    def migrate_macs(self):
        """2. Migrate the m.mac_address -> q.quark_mac_addresses
        This is the next simplest but the relationship between quark_networks
        and quark_mac_addresses may be complicated to set up (if it exists)
        """
        """Only migrating the first mac_address_range from melange."""
        mac_range = self.session.query(melange.MacAddressRanges).first()
        cidr = mac_range.cidr
        cidr, first_address, last_address = self._to_mac_range(cidr)

        q_range = quarkmodels.MacAddressRange(id=mac_range.id,
                                              cidr=cidr,
                                              created_at=mac_range.created_at,
                                              first_address=first_address,
                                              next_auto_assign_mac=first_address,  # noqa
                                              last_address=last_address)
        self.session.add(q_range)

        res = self.session.query(melange.MacAddresses).all()
        no_network_count = 0
        for mac in res:
            if mac.interface_id not in self.interface_network:
                no_network_count += 1
                log.info("mac.interface_id {0} not in self.interface_network"
                         .format(mac.interface_id))
                continue
            tenant_id = self.interface_tenant[mac.interface_id]
            q_mac = quarkmodels.MacAddress(tenant_id=tenant_id,
                                           created_at=mac.created_at,
                                           mac_address_range_id=mac_range.id,
                                           address=mac.address)
            q_port = self.port_cache[mac.interface_id]
            q_port.mac_address = q_mac.address
            self.session.add(q_mac)
        log.info("skipped {0} mac addresses".format(str(no_network_count)))

    def _octet_to_cidr(self, octet, ipv4_compatible=False):
        """
        Convert an ip octet to a ipv6 cidr
        """
        ipnet = netaddr.IPNetwork(
            netaddr.cidr_abbrev_to_verbose(octet)).ipv6(
            ipv4_compatible=ipv4_compatible)
        return str(ipnet.ip)

    def migrate_policies(self):
        """
        Migrate melange policies to quark ip policies
            * Only one policy allowed per network
            * Only one policy allowed per subnet
            * Subnet policies take precedence over network policies in software
        ==== STEPS: ====
        1. get a block (including cidr, id, etc)
        2. get the blocks policy
        3. get the policy ip_octets and/or ip_ranges (possibly many)
        4. convert the block.cidr (if ipv4) to ipv6
        5. convert the octet(s) to range(s)
        6. if there are ranges and octets, simplify the policies
        7. determine if the block is a subnet or a network
        8. for every new policy:
            8.1. create a new quark_ip_policy
            8.2. for every new range:
                8.2.1. create a new quark_ip_policy_range
            8.3. associate the policy_range with the policy
            8.4 associate the policy with the network or subnet
        """
        possible = 0
        covered = 0
        octets = melange.IpOctets
        ranges = melange.IpRanges
        blocks = melange.IpBlocks
        # these cover 99% of the policies currently:
        # version: ipv4
        # offset: -1
        # length: 3
        # This creates a policy encompassing .0, .1, and .255
        # In melange, this was a policy with just offset:0 length:1
        # If there is only policy octet: 0, same thing.
        q_default_offset = -1
        q_default_length = 3
        for policy, policy_block_ids in self.policy_ids.items():
            octet_list = list()
            range_list = list()
            block_dict = dict()
            policy_octets = self.session.query(octets).\
                filter(octets.policy_id == policy).all()
            for policy_block_id in policy_block_ids:
                block = self.session.query(blocks).\
                    filter(blocks.id == policy_block_id).all()
                for b in block:
                    block_dict.update({b.id: b.cidr})
            policy_ranges = self.session.query(ranges).\
                filter(ranges.policy_id == policy).all()
            if policy_octets:
                for policy_octet in policy_octets:
                    octet_list.append(policy_octet.octet)
            if policy_ranges:
                for policy_range in policy_ranges:
                    range_list.append((policy_range.offset,
                                       policy_range.length))
            for block_id, block_cidr in block_dict.items():
                possible += 1
                other_version_cidr = None
                q_version = None
                q_offset = None
                q_length = None
                # ipv6 has :'s, v4 doesn't.
                if ':' in block_cidr:
                    q_version = 6
                else:
                    q_version = 4
                try:
                    if q_version == 6:
                        other_version_cidr = str(netaddr
                                                 .IPNetwork(block_cidr).ipv4())
                    else:
                        other_version_cidr = str(netaddr
                                                 .IPNetwork(block_cidr).ipv6())
                except:
                    log.error("Couldn't convert cidr {0}".format(block_cidr))

                if (octet_list == [0] and not range_list) or\
                        (range_list == [(0, 1)] and not octet_list):
                    # default range stuff
                    q_offset, q_length = q_default_offset, q_default_length
                    covered += 1.0
                    continue
                elif range_list and not octet_list:
                    for range_pair in range_list:
                        if range_pair[0] * -1 == range_pair[1]:
                            q_offset = range_pair[0]
                            q_length = range_pair[1]
                            covered += 1
                            break
                elif octet_list and not range_list:
                    for octet in octet_list:
                        pass  # TODO do something with octets
                        # they literally abused octets
                log.debug("Migrating policy: policy_id {0}\n"
                          "\tversion {1}, offset {2}, length {3}\n"
                          "\tblock_id: {4}\n"
                          "\tblock cidr: {5}\n"
                          "\tother cidr: {6}\n"
                          .format(policy,
                                  q_version,
                                  q_offset,
                                  q_length,
                                  block_id,
                                  block_cidr,
                                  other_version_cidr))
                # self.session.add(subn)
        log.debug("Policies covered in migration: {0}"
                  .format((covered/possible)*100))
        log.warning("Policies not migrated, awaiting clarification... TODO")

    def migrate_commit(self):
        """4. Commit the changes to the database"""
        self.session.commit()

    def migrate(self):
        """
        This will migrate an existing melange database to a new quark
        database. Below melange is referred to as m and quark as q.
        """
        totes = 0.0
        totes += self.do_and_time("migrate networks, subnets, routes, and ips",
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
        log.info("TOTAL: {0} seconds.".format(str(totes)))
        log.debug("Done.")
