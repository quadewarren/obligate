import logging as log
from sqlalchemy.orm import sessionmaker
from models import melange
import datetime
import os
import sys


def logit():
    log_format = "{} {}\t{}\t{}".format('%(asctime)s',
                                        '%(levelname)s',
                                        '%(funcName)s',
                                        '%(message)s')
    log_dateformat = '%m/%d/%Y %I:%M:%S %p'
    file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
    now = datetime.datetime.now()
    # basepath = os.path.dirname(os.path.realpath(__file__))
    filename_format = 'logs/obligate.{}.log'\
        .format(now.strftime(file_timeformat))
    # create the logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('/logs')
    log.basicConfig(format=log_format,
                    datefmt=log_dateformat,
                    filename=filename_format,
                    filemode='w',
                    level=log.DEBUG)

    root = log.getLogger()
    ch = log.StreamHandler(sys.stdout)
    ch.setLevel(log.DEBUG)
    formatter = log.Formatter(log_format)
    ch.setFormatter(formatter)
    root.addHandler(ch)


def loadSession():
    #metadata = Base.metadata
    log.debug("Connecting to database via sqlalchemy.")
    Session = sessionmaker(bind=melange.engine)
    session = Session()
    log.debug("Connected to database.")
    return session


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
        return [(all_items[0], all_items[0]+1)]
    stack.append(all_items[0])
    for c, i in enumerate(all_items[1:], start=1):
        if i - 1 == stack[-1]:
            stack.append(i)
        else:
            retvals.append((stack[0], stack[-1]+1))
            stack = list()
            stack.append(i)
    retvals.append((stack[0], stack[-1]+1))
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
    offset_length is a format like a range, but indicates the offset (from 0)
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

    """
    import netaddr
    cidr_parts = val.split("/")
    prefix = cidr_parts[0]
    prefix = prefix.replace(':', '')
    prefix = prefix.replace('-', '')
    prefix_length = len(prefix)
    if prefix_length < 6 or prefix_length > 10:
        r = "6>len({0}) || len({0})>10 [len == {1}]".format(val, prefix_length)
        # raise quark_exceptions.InvalidMacAddressRange(cidr=val)
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
        #raise quark_exceptions.InvalidMacAddressRange(cidr=val)
        return None, r, None
    prefix_int = int(prefix, base=16)
    return cidr, prefix_int, prefix_int + mask_size


if __name__ == "__main__":
    import doctest
    doctest.testmod()
