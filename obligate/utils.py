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


if __name__ == "__main__":
    import doctest
    doctest.testmod()
