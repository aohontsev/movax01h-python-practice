"""
This file contains implementation of bubble sort algorithm describes here
https://en.wikipedia.org/wiki/Bubble_sort
"""

_author_ = "anton.ohontsev@gmail.com"


def sort(array):
    """Sorting array via bubble algorithm.

    Args:
        array: An unsorted list.

    Returns:
        Sorted array from smallest to largest.
    """
    if not array:
        return array

    keep_going = True
    while keep_going:
        keep_going = False
        for idx in range(len(array) - 1):
            val = array[idx]
            next_idx = idx + 1
            next_val = array[next_idx]
            if val > next_val:
                array[idx] = next_val
                array[next_idx] = val
                keep_going = True

    return array
