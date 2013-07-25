import logging as log
# import sys
import os
import datetime

log_format = "{} {}\t{}\t{}".format('%(asctime)s',
                                    '%(levelname)s',
                                    '%(funcName)s',
                                    '%(message)s')
log_dateformat = '%m/%d/%Y %I:%M:%S %p'
file_timeformat = "%A-%d-%B-%Y--%I.%M.%S.%p"
now = datetime.datetime.now()
filename_format = 'logs/obligate.{}.log'.format(now.strftime(file_timeformat))
# create the logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')
log.basicConfig(format=log_format,
                datefmt=log_dateformat,
                filename=filename_format,
                filemode='w',
                level=log.DEBUG)
"""
root = log.getLogger()
ch = log.StreamHandler(sys.stdout)
ch.setLevel(log.DEBUG)
formatter = log.Formatter(log_format)
ch.setFormatter(formatter)
root.addHandler(ch)
"""


def octets_to_ranges(octets=None, ranges=None):
    """
    Combine all the octets and ranges into the smallest possible
    set of ranges. The maximum in range is 255.

    >>> octets_to_ranges(octets=[2, 3, 4], ranges=None)
    [(2, 5)]

    >>> octets_to_ranges([2, 4])
    [(2, 3), (4, 5)]

    # >>> octets_to_ranges([2, 3, 4, 5, 6, 7, 9, 10, 11, 12])
    [(2, 8), (9, 13)]

    >>> octets_to_ranges([1], ranges=[(1, 2)])
    [(1, 2)]

    """
    # import pdb
    # pdb.set_trace()
    octets.sort()
    log.debug("=======\n\t\t\tOctets created: {0}".format(octets))
    tmp_pairs = list()
    retvals = list()
    # build the pairs
    for octet in octets:
        tmp_pairs.append((octet, octet+1))
    log.debug("tmp_pairs created: {0}".format(tmp_pairs))
    prev_pair = None
    range_min = None
    range_max = None
    for i, pair in enumerate(tmp_pairs, start=1):
        log.debug("-L64: i:{0} pair:{1}".format(i, pair))
        final_pair = i == len(tmp_pairs)
        log.debug("-L66: final_pair:{0}".format(final_pair))
        log.debug("-L67: prev_pair:{0}".format(prev_pair))
        if not prev_pair:
            log.debug("-L69:\tnot prev pair...")
            # this is the first pair
            prev_pair = pair
            range_min = pair[0]
            range_max = pair[1]
            log.debug("-L75: prev_pair:{0} range_min:{1} range_max:{2}"
                      .format(prev_pair, range_min, range_max))
        elif pair[0] == prev_pair[1]:  # and not final_pair:
            log.debug("-L77:\tpair[0]==prev_pair[1] & !final_pair...")
            # the range continues
            prev_pair = pair
            range_max = pair[1]
            log.debug("-L81: prev_pair:{0} range_max: {1}"
                      .format(prev_pair, range_max))
        if final_pair:
            log.debug("-L84:\tfinal_pair...")
            # reached the end of the pairs
            retvals.append((range_min, range_max))
            log.debug("-L87: retvals appended: {0}"
                      .format(retvals))
        else:
            log.debug("-L90:\tnot final pair...")
            # not at the end of the pairs
            retvals.append((range_min, range_max))
            log.debug("-L93: retvals appended: {0}"
                      .format(retvals))
            prev_pair = None
            log.debug("-L96: prev_pair: {0}"
                      .format(prev_pair))
    log.debug("++++++++\n\t\t\tDone. Retvals: {0}".format(retvals))
    return retvals


if __name__ == "__main__":
    # octets_to_ranges([2, 3, 4, 5, 6, 7, 9, 10, 11, 12])
    # print
    # octets_to_ranges([2, 4])
    import doctest
    doctest.testmod()
