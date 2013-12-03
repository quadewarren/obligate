import requests
from requests.auth import HTTPBasicAuth


class MysqlJsonBridgeEndpoint(object):
    def run_query(self, sql):
        data = {'sql': sql}
        r = self.session.post(self.url, data=data,
                              verify=False, auth=self.auth)
        self.calls += 1
        r.raise_for_status()
        return r.json()['result']

    def first_result(self, result):
        try:
            return result[0]
        except (TypeError, IndexError, KeyError):
            return None


class Melange(MysqlJsonBridgeEndpoint):
    def __init__(self, url, username, password):
        self.url = url
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.session()
        self.calls = 0

    def get_interface_by_id(self, id):
        sql = 'select device_id from interfaces where id="%s"'
        result = self.run_query(sql % id)
        return self.first_result(result)

    def get_interfaces(self):
        select_list = ['interfaces.id', 'mac_addresses.address as mac',
                       'device_id',
                       'group_concat(ip_addresses.address) as ips']
        sql = ('select %s from interfaces left join mac_addresses '
               'on interfaces.id=mac_addresses.interface_id left join '
               'ip_addresses on interfaces.id=ip_addresses.interface_id '
               'group by interfaces.id')
        return self.run_query(sql % ','.join(select_list))

    def get_interfaces_hashed_by_id(self):
        return dict((interface['id'], interface)
                    for interface in self.get_interfaces())

    def get_interfaces_hashed_by_device_id(self):
        return dict((interface['device_id'], interface)
                    for interface in self.get_interfaces())


class Nova(MysqlJsonBridgeEndpoint):
    def __init__(self, url, username, password):
        self.url = url
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.session()
        self.calls = 0

    def get_instance_by_id(self, id):
        select_list = ['uuid', 'vm_state', 'terminated_at', 'cell_name']
        sql = 'select %s from instances where uuid="%s" and deleted=0'
        result = self.run_query(sql % (','.join(select_list), id))
        return self.first_result(result)

    def get_instances(self):
        select_list = ['uuid', 'vm_state', 'terminated_at', 'cell_name']
        sql = 'select %s from instances where deleted=0'
        return self.run_query(sql % ','.join(select_list))

    def get_instances_hashed_by_id(self):
        return dict((instance['uuid'], instance)
                    for instance in self.get_instances())
