import atexit
import ConfigParser as cfgp
import datetime
import glob
import json
import logging
import math
import netaddr
import os
from sqlalchemy.orm import sessionmaker
import subprocess


def get_basepath():
    basepath = os.path.dirname(os.path.realpath(__file__))
    basepath = os.path.abspath(os.path.join(basepath, os.pardir))
    return basepath


log_format = "{} {} {} line {} {}".format('%(asctime)-25s',
                                          '%(levelname)-8s',
                                          '%(funcName)-20s',
                                          '%(lineno)-7s',
                                          '%(message)-4s')
log_dateformat = '%m/%d/%Y %I:%M:%S %p'
file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
now = datetime.datetime.now()
basepath = get_basepath()
filename_format = '{}/logs/obligate.{}.log'\
    .format(basepath, now.strftime(file_timeformat))

# create the logs directory if it doesn't exist
if not os.path.exists('{}/logs'.format(basepath)):
    os.makedirs('{}/logs'.format(basepath))


def start_logging(verbose=False):
    logging.basicConfig(format=log_format,
                        datefmt=log_dateformat,
                        filename=filename_format,
                        filemode='w',
                        level=logging.DEBUG)
    root = logging.getLogger()
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(funcName)s(%(lineno)d): %(message)s')  # noqa
    console.setFormatter(formatter)
    if verbose:
        root.addHandler(console)

ulog = logging.getLogger('obligate.utils')
basepath = os.path.dirname(os.path.realpath(__file__))
basepath = os.path.abspath(os.path.join(basepath, os.pardir))

config = cfgp.ConfigParser()
config_file_path = "{}/.config".format(basepath)
config.read(config_file_path)
min_ram_mb = config.get('system_reqs', 'min_ram_mb', '4000')
migrate_tables = config.get('migration', 'tables', ('networks',
                                                    'subnets',
                                                    'routes',
                                                    'ips',
                                                    'interfaces',
                                                    'mac_ranges',
                                                    'macs',
                                                    'policies',
                                                    'policy_rules'))
migrate_tables = migrate_tables.splitlines()[1:]


def clear_logs():
    # deletes all the log files
    ulog.info("Clear logfiles requests ('-c')...")
    logdir = '{}/logs'.format(basepath)
    if os.path.exists(logdir):
        files = glob.glob(logdir + '/*')
        for f in files:
            os.remove(f)
            ulog.info("{} deleted.".format(f.split('/')[-1]))


def _octet_to_cidr(self, octet, ipv4_compatible=False):
    """
    Convert an ip octet to a ipv6 cidr
    This may be dead code, not used anywhere.
    """
    ipnet = netaddr.IPNetwork(
        netaddr.cidr_abbrev_to_verbose(octet)).\
        ipv6(ipv4_compatible=ipv4_compatible)
    return str(ipnet.ip)


def build_json_structure(tables=migrate_tables):
    json_data = dict()
    for table in tables:
        json_data[table] = {'num migrated': 0,
                            'ids': dict()}
    return json_data


def dump_json(data):
    file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
    now = datetime.datetime.now()
    filename = 'logs/obligate.{}'.format(now.strftime(file_timeformat))
    for tablename in migrate_tables:
        with open('{}.{}.json'.format(filename, tablename), 'wb') as fh:
            json.dump(data[tablename], fh)


def incr_num(json_data, tablename):
    json_data[tablename]['num migrated'] += 1
    return json_data


def migrate_id(json_data, tablename, id):
    try:
        json_data[tablename]['ids'][id]['migrated'] = True
        json_data[tablename]['ids'][id]['migration count'] -= 1
        json_data = incr_num(json_data, tablename)
    except Exception:
        ulog.error("Key {} not in {}".format(id, tablename))
    return json_data


def translate_netmask(netmask, destination):
    """
    In [64]: a = netaddr.IPAddress("255.240.0.0") # <- netmask
    In [65]: netaddr.IPNetwork("192.168.0.0/%s" %
        (32 - int(math.log(2**32 - a.value, 2))))
    Out[65]: IPNetwork('192.168.0.0/12')
    So if the destination address is 192.168.0.0
    Thats your cidr
    """
    # returns a cidr based on the string arguments
    if not netmask:
        ulog.error("No netmask given.")
    if not destination:
        ulog.error("No destination given.")
    try:
        a = netaddr.IPAddress(netmask)
        return str(netaddr.IPNetwork("{}/{}".format(destination, 32 - int(math.log(2 ** 32 - a.value, 2)))))  # noqa
    except Exception:
        ulog.critical("Could not generate cidr, netmask {} destination {}".
                      format(netmask, destination))


def trim_br(network_id):
    if network_id[:3] == "br-":
        return network_id[3:]
    return network_id


def has_enough_ram():
    free = subprocess.Popen(['free', '-m'],
                            stdout=subprocess.PIPE).communicate()[0].splitlines()  # noqa
    totes_ram = int(free[1].strip().split()[1])
    if totes_ram >= int(min_ram_mb):
        return True
    return False


def loadSession(engine):
    """no doc."""
    ulog.debug("Connecting to database {}...".format(engine))
    Session = sessionmaker(bind=engine)
    session = Session()
    ulog.debug("Connected to database {}.".format(engine))
    return session


def offset_to_range(offset):
    """
    no doc.

    >>> offset_to_range((1, 2))
    (1, 3)

    >>> offset_to_range((3, 1))
    (3, 4)
    """
    return (offset[0], offset[0] + offset[1])


def make_offset_lengths(octets, offsets):
    """
    TDD FTW.

    >>> o = []
    >>> r = [(0,1)]
    >>> make_offset_lengths(o, r)
    [(0, 1)]

    >>> r = [(-1, 2)]
    >>> make_offset_lengths(o, r)
    [(-1, 2)]

    >>> r = [(5, 10), (11, 20)]
    >>> o = [255, 4]
    >>> make_offset_lengths(o, r)
    [(4, 27), (255, 1)]

    >>> r = [(5, 10), (11, 20)]
    >>> o = [255, 3]
    >>> make_offset_lengths(o, r)
    [(3, 1), (5, 26), (255, 1)]
    """
    tmp_ranges = list()
    tmp_or = list()
    if offsets:
        for o in offsets:
            tmp_ranges.append(offset_to_range(o))
    if octets:
        tmp_or = list_to_ranges(octets)
        for r in tmp_or:
            tmp_ranges.append(r)
    tmp_all = consolidate_ranges(tmp_ranges)
    return ranges_to_offset_lengths(tmp_all)


def list_to_ranges(the_list=None):
    """
    Combine all the integers into the smallest possible set of ranges.

    >>> list_to_ranges(the_list=[2, 3, 4])
    [(2, 5)]

    >>> list_to_ranges([2, 4])
    [(2, 3), (4, 5)]

    >>> list_to_ranges([2, 3, 4, 5, 6, 7, 9, 10, 11, 12])
    [(2, 8), (9, 13)]

    >>> list_to_ranges([1])
    [(1, 2)]

    """
    retvals = list()
    all_items = list()
    stack = list()
    for o in the_list:
        all_items.append(o)
    all_items.sort()
    if len(all_items) == 1:
        return [(all_items[0], all_items[0] + 1)]
    stack.append(all_items[0])
    for c, i in enumerate(all_items[1:], start=1):
        if i - 1 == stack[-1]:
            stack.append(i)
        else:
            retvals.append((stack[0], stack[-1] + 1))
            stack = list()
            stack.append(i)
    retvals.append((stack[0], stack[-1] + 1))
    return retvals


def consolidate_ranges(the_ranges):
    """
    Given a list of range values, return the fewest number of ranges that
    include the same coverage.

    >>> consolidate_ranges([(1, 2)])
    [(1, 2)]

    >>> consolidate_ranges([(6, 9), (3, 6)])
    [(3, 9)]

    >>> consolidate_ranges([(5, 12), (1, 6)])
    [(1, 12)]

    >>> consolidate_ranges([(1, 12), (1, 9), (16, 25), (12, 13)])
    [(1, 13), (16, 25)]

    """
    if not the_ranges:
        return []
    if the_ranges[0] == 255:
        the_ranges[0] = -1
    if len(the_ranges) < 2:
        return the_ranges
    the_ranges = sorted(the_ranges, key=lambda ran: ran[0])
    retvals = list()
    for r in the_ranges:
        if r[1] - r[0] == 1:
            retvals.append(r[0])
        else:
            for n in range(r[0], r[1]):
                retvals.append(n)
    retvals = set(retvals)
    retvals = list_to_ranges(retvals)
    return retvals


def ranges_to_offset_lengths(ranges):
    """
    offset_length is like a range, but indicates the offset (from 0)
    and the length of the coverage.

    >>> ranges_to_offset_lengths([(1, 5)])
    [(1, 4)]

    >>> ranges_to_offset_lengths([(3, 15)])
    [(3, 12)]

    >>> ranges_to_offset_lengths([(6, 7), (10, 100)])
    [(6, 1), (10, 90)]
    """
    retvals = list()
    for r in ranges:
        retvals.append((r[0], r[1] - r[0]))
    return retvals


def to_mac_range(val):
    """
    Doc Tests.

    >>> testval1 = "AA:AA:AA/8"
    >>> testval2 = "12-23-45/9"
    >>> testval3 = "::/0"
    >>> testval4 = "00-00-00-00/10"

    >>> to_mac_range(testval1)
    ('AA:AA:AA:00:00:00/8', 187649973288960, 188749484916736)

    >>> to_mac_range(testval2)
    ('12:23:45:00:00:00/9', 19942690783232, 20492446597120)

    This should fail:
    >>> to_mac_range(testval3)
    Traceback (most recent call last):
        ...
    ValueError: 6>len(::/0) || len(::/0)>10 [len == 0]

    this should not fail:
    >>> to_mac_range(testval4)
    ('00:00:00:00:00:00/10', 0, 274877906944)

    bad cidr:
    >>> badcidr = "ZZZZZZ"
    >>> to_mac_range(badcidr) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
        ...
    AddrFormatError: ZZZZZZ000000 raised netaddr.AddrFormatError:
        failed to detect EUI version: 'ZZZZZZ000000'... ignoring.

    """
    import netaddr
    cidr_parts = val.split("/")
    prefix = cidr_parts[0]
    prefix = prefix.replace(':', '')
    prefix = prefix.replace('-', '')
    prefix_length = len(prefix)
    if prefix_length < 6 or prefix_length > 12:
        r = "6>len({0}) || len({0})>12 len == {1}]".format(val, prefix_length)
        raise ValueError(r)
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
        r = "{} raised netaddr.AddrFormatError: ".format(prefix)
        r += "{}... ignoring.".format(e.message)
        raise netaddr.AddrFormatError(r)
    prefix_int = int(prefix, base=16)
    del netaddr
    return cidr, prefix_int, prefix_int + mask_size


def done():
    ulog.info('Done, exiting.')
    ulog.info('-' * 20)

atexit.register(done)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
