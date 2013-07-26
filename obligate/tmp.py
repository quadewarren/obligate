
def octets_to_ranges(octets=None):
    """
    Combine all the octets and ranges into the smallest possible
    set of ranges. The maximum in range is 255.

    >>> octets_to_ranges(octets=[2, 3, 4])
    [(2, 5)]

    >>> octets_to_ranges([2, 4])
    [(2, 3), (4, 5)]

    >>> octets_to_ranges([2, 3, 4, 5, 6, 7, 9, 10, 11, 12])
    [(2, 8), (9, 13)]

    >>> octets_to_ranges([1])
    [(1, 2)]

    23:05:45 roaet | sort them ascending
23:05:59 roaet | [1,2,4,5,6,9,10]
23:06:00 roaet | sorted
23:06:14 roaet | get the first number a push it onto a stack (list)
23:06:20 roaet | S = [1]
23:06:29 roaet | loop through the rest
23:06:32 roaet | so 2.. 10
23:06:46 roaet | check if the number is 1 greater than the number in the stack
23:06:52 roaet | if it is push it into the stack
23:06:55 roaet | S = [1,2]
23:06:58 roaet | check again
23:07:07 roaet | if the number is 1 greater than the number
                 (on the top) of the stack
23:07:15 roaet | (modifying my previous check to on top of stack)
23:07:22 roaet | 4  != 2 + 1
23:07:33 roaet | The top and bottom of the stack is your range
23:07:37 roaet | (1,2)
23:07:48 roaet | make the stack your range, put it into a list, empty the stack
23:07:49 roaet | S = []
23:07:53 roaet | push 4 into the stack
23:07:58 roaet | S = [4]
23:08:00 roaet | continue loop
23:08:08 roaet | S = [4,5,6]
23:08:19 roaet | 9 != 6+1
    """
    retvals = list()
    all_octets = list()
    stack = list()
    for o in octets:
        all_octets.append(o)
    all_octets.sort()
    if len(all_octets) == 1:
        return [(all_octets[0], all_octets[0]+1)]
    stack.append(all_octets[0])
    for c, i in enumerate(all_octets[1:], start=1):
        # loop through rest of stack
        # check if one greater than top of stack
        if i - 1 == stack[-1]:
            # if it is, push onto stack
            stack.append(i)
        else:
            # otherwise, bottom and top of stack are range
            retvals.append((stack[0], stack[-1]+1))
            stack = list()
            stack.append(i)
        if c == len(all_octets) - 1:
            # this is the magic sauce right cheur
            retvals.append((stack[0], stack[-1]+1))

    return retvals


if __name__ == "__main__":
    import doctest
    doctest.testmod()
