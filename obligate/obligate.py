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
from datetime import datetime as dt
import logging
from models import melange, neutron
import netaddr
from quark.db import models as quarkmodels
import resource
import time
import traceback

from utils import build_json_structure
from utils import dump_json
from utils import flush_db
from utils import init_id
from utils import make_offset_lengths
from utils import migrate_id
from utils import set_reason
from utils import to_mac_range
from utils import translate_netmask
from utils import trim_br


class Obligator(object):
    def __init__(self, melange_sess=None, neutron_sess=None):
        self.commit_tick = 0
        self.max_records = 75000
        self.interface_tenant = dict()
        self.interfaces = dict()
        self.interface_network = dict()
        self.interface_ip = dict()
        self.port_cache = dict()
        self.policy_ids = dict()
        self.melange_session = melange_sess
        self.neutron_session = neutron_sess
        self.json_data = build_json_structure()
        res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.log = logging.getLogger('obligate.obligator')
        self.log.debug("Ram used: {:0.2f}M".format(res / 1024.0))


    def do_and_time(self, label, fx, **kwargs):
        start_time = time.time()
        self.log.info("start: {}".format(label))
        try:
            fx(**kwargs)
        except Exception as e:
            self.error_free = False
            self.log.critical("Error during"
                              " {}:{}\n{}".format(label,
                                                  e.message,
                                                  traceback.format_exc()))
        end_time = time.time()
        self.log.info("end  : {}".format(label))
        self.log.info("delta: {} = {:.2f} seconds".format(label,
                                                          end_time - start_time))  # noqa
        res = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        self.log.debug("Ram used: {:0.2f}M".format(res / 1000.0))
        return end_time - start_time

    def add_to_session(self, item, tablename, id):
        self.commit_tick += 1
        self.json_data = migrate_id(self.json_data, tablename, id)
        self.neutron_session.add(item)
        if ((self.commit_tick + 1) % self.max_records == 0):
            self.commit_tick = 0
            self.migrate_commit()

    def new_to_session(self, item, tablename):
        # add something brand new to the database
        self.commit_tick += 1
        self.json_data[tablename]['num migrated'] += 1
        self.json_data[tablename]['new'] += 1
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
        for block in blocks:
            init_id(self.json_data, 'networks', trim_br(block.network_id))
            if trim_br(block.network_id) not in networks:
                networks[trim_br(block.network_id)] = {
                    "tenant_id": block.tenant_id,
                    "name": block.network_name,
                    "max_allocation": block.max_allocation}
            elif networks[trim_br(
                    block.network_id)]["tenant_id"] != block.tenant_id:
                r = "Found different tenant on network:{0} != {1}"\
                    .format(networks[trim_br(
                        block.network_id)]["tenant_id"],
                        block.tenant_id)
                self.log.critical(r)
                set_reason(self.json_data, 'networks',
                           trim_br(block.network_id), r)
                raise Exception
        for net in networks:
            cache_net = networks[net]
            q_network = quarkmodels.Network(id=net,
                                            tenant_id=cache_net["tenant_id"],
                                            name=cache_net["name"],
                                            max_allocation=
                                            cache_net["max_allocation"])
            self.add_to_session(q_network, 'networks', net)
        blocks_without_policy = 0
        for block in blocks:
            init_id(self.json_data, 'subnets', block.id)
            q_subnet = quarkmodels.Subnet(id=block.id,
                                          network_id=
                                          trim_br(block.network_id),
                                          tenant_id=block.tenant_id,
                                          cidr=block.cidr,
                                          do_not_use=block.omg_do_not_use,
                                          created_at=block.created_at)
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
                self.log.warning("Found block without a policy: {0}"
                                 .format(block.id))
                blocks_without_policy += 1
        # have to add new routes as well:
        new_gates = 0
        for block in blocks:
            if block.gateway:
                self.migrate_new_routes(block)
                new_gates += 1
        self.log.info("Cached {0} policy_ids. {1} blocks found without policy."
                      .format(len(self.policy_ids), blocks_without_policy))
        self.log.info("{} brand new gateways created.".format(new_gates))

    def migrate_routes(self, block=None):
        routes = self.melange_session.query(melange.IpRoutes)\
            .filter_by(source_block_id=block.id).all()
        for route in routes:
            init_id(self.json_data, 'routes', route.id)
            q_route = quarkmodels.Route(id=route.id,
                                        cidr=
                                        translate_netmask(route.netmask,
                                                          route.destination),
                                        tenant_id=block.tenant_id,
                                        gateway=route.gateway,
                                        created_at=block.created_at,
                                        subnet_id=block.id,
                                        created_at=route.created_at)
            self.add_to_session(q_route, 'routes', q_route.id)

    def migrate_new_routes(self, block=None):
        gateway = netaddr.IPAddress(block.gateway)
        destination = None
        if gateway.version == 4:
            destination = '0.0.0.0/0'  # 3
        else:
            destination = '0:0:0:0:0:0:0:0/0'  # 4
        q_route = quarkmodels.Route(cidr=destination,
                                    tenant_id=block.tenant_id,
                                    gateway=block.gateway,
                                    subnet_id=block.id,
                                    created_at=dt.utcnow())
        self.new_to_session(q_route, 'routes')

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
            init_id(self.json_data, 'ips', address.id)
            """Populate interface_network cache"""
            interface = address.interface_id
            if interface is not None and\
                    interface not in self.interface_network:
                self.interface_network[interface] = \
                    trim_br(block.network_id)
            if interface in self.interface_network and\
                    self.interface_network[interface] != \
                    trim_br(block.network_id):
                self.log.error("Found interface with different "
                               "network id: {0} != {1}"
                               .format(self.interface_network[interface],
                                       trim_br(block.network_id)))
            deallocated = False
            deallocated_at = None
            # If marked for deallocation
            #       put it into the quark ip table as deallocated
            if address.marked_for_deallocation == 1:
                deallocated = True
                deallocated_at = address.deallocated_at

            ip_address = netaddr.IPAddress(address.address)
            q_ip = quarkmodels.IPAddress(id=address.id,
                                         created_at=address.created_at,
                                         used_by_tenant_id=
                                         address.used_by_tenant_id,
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
        self.log.critical("NVP_TEMP_KEY needs to be updated.")
        for interface in interfaces:
            init_id(self.json_data, "interfaces", interface.id)
            if interface.id not in self.interface_network:
                set_reason(self.json_data, "interfaces",
                           interface.id, "no network")
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
        self.log.info("Found {0} interfaces without a network."
                      .format(str(no_network_count)))

    def associate_ips_with_ports(self):
        """This is a time-consuming little function and begs to be optimized
        111,600+ iterations @ 1,000 seconds in DFW
        """
        for port in self.port_cache:
            q_port = self.port_cache[port]
            for ip in self.interface_ip[port]:
                # q_port.ip_addresses.append(ip)
                pass

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
        init_id(self.json_data, 'mac_ranges', mac_range.id)
        try:
            cidr, first_address, last_address = to_mac_range(cidr)
        except ValueError as e:
            set_reason(self.json_data, mac_range.id, "mac_ranges", e.message)
            self.log.critical(e.message)
            return None
        except netaddr.AddrFormatError as afe:
            set_reason(self.json_data, mac_range.id, "mac_ranges", afe.message)
            self.log.critical(afe.message)
            return None
        q_range = quarkmodels.MacAddressRange(id=mac_range.id,
                                              cidr=cidr,
                                              created_at=mac_range.created_at,
                                              first_address=first_address,
                                              next_auto_assign_mac=
                                              first_address,
                                              last_address=last_address)
        self.add_to_session(q_range, 'mac_ranges', q_range.id)
        res = self.melange_session.query(melange.MacAddresses).all()
        no_network_count = 0
        for mac in res:
            init_id(self.json_data, 'macs', mac.address)
            if mac.interface_id not in self.interface_network:
                no_network_count += 1
                r = "mac.interface_id {0} not in self.interface_network"\
                    .format(mac.interface_id)
                set_reason(self.json_data, 'macs', mac.address, r)
                continue
            tenant_id = self.interface_tenant[mac.interface_id]
            q_mac = quarkmodels.MacAddress(tenant_id=tenant_id,
                                           created_at=mac.created_at,
                                           mac_address_range_id=mac_range.id,
                                           address=mac.address)
            q_port = self.port_cache[mac.interface_id]
            q_port.mac_address = q_mac.address
            self.add_to_session(q_mac, 'macs', q_mac.address)
        self.log.info("skipped {0} mac addresses".format(str(no_network_count)))  # noqa

    def migrate_policies(self):
        """
        Migrate policies

        We exclude the default policies.  These are octets that are 0 or
        ip ranges that have offset 0 and length 1.

        This is another time-consuming function, but optimization will not
        yeild as much fruit as optimizing associate_ips_with_ports()

        There is a minute or two of lag while this spins up, may be a way
        to negate this.
        """
        from uuid import uuid4
        octets = self.melange_session.query(melange.IpOctets).all()
        offsets = self.melange_session.query(melange.IpRanges).all()
        for policy, policy_block_ids in self.policy_ids.items():
            policy_octets = [o.octet for o in octets if o.policy_id == policy]
            policy_rules = [(off.offset, off.length) for off in offsets
                            if off.policy_id == policy]
            policy_rules = make_offset_lengths(policy_octets, policy_rules)
            a = [o.created_at for o in octets if o.policy_id == policy]
            b = [off.created_at for off in offsets if off.policy_id == policy]
        
            try:
                oct_created_at = min(a)
            except Exception:
                oct_created_at = dt.utcnow()
            try:
                ran_created_at = min(b)
            except Exception:
                ran_created_at = dt.utcnow()
            min_created_at = min([oct_created_at, ran_created_at])
            try:
                policy_description = self.melange_session.query(
                    melange.Policies.description).\
                    filter(melange.Policies.id == policy).first()[0]
            except Exception:
                policy_description = None
            for block_id in policy_block_ids.keys():
                policy_uuid = str(uuid4())
                init_id(self.json_data, 'policies', policy_uuid)
                q_network = self.neutron_session.query(quarkmodels.Network).\
                    filter(quarkmodels.Network.id ==
                           policy_block_ids[block_id]).first()
                q_ip_policy = quarkmodels.IPPolicy(id=policy_uuid,
                                                   tenant_id=
                                                   q_network.tenant_id,
                                                   description=
                                                   policy_description,
                                                   created_at=
                                                   min_created_at)
                q_ip_policy.networks.append(q_network)
                q_subnet = self.neutron_session.query(quarkmodels.Subnet).\
                    filter(quarkmodels.Subnet.id == block_id).first()
                q_ip_policy.subnets.append(q_subnet)
                self.add_to_session(q_ip_policy, 'policies', policy_uuid)
                for rule in policy_rules:
                    offset_uuid = str(uuid4())
                    init_id(self.json_data, 'policy_rules', offset_uuid)
                    q_ip_policy_rule = quarkmodels.\
                        IPPolicyRange(id=offset_uuid,
                                      offset=rule[0],
                                      length=rule[1],
                                      ip_policy_id=policy_uuid,
                                      created_at=min_created_at)
                    self.add_to_session(q_ip_policy_rule, 'policy_rules',
                                        offset_uuid)

    def migrate_commit(self):
        """4. Commit the changes to the database"""
        self.neutron_session.commit()
        self.log.debug("neutron_session.commit() complete.")

    def migrate(self):
        """
        This will migrate an existing melange database to a new quark
        database. Below melange is referred to as m and quark as q.
        """
        totes = 0.0
        flush_db()
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
        self.log.info("TOTAL: {0:.2f} seconds.".format(totes))
        dump_json(self.json_data)
