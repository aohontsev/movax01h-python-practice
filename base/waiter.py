"""
This file contains utils for
"""

import time

__author__ = "anton.ohontsev@gmail.com"


def waiter_poll(timeout, func, *args, **kwargs):
    """Waits while given function returns value that can be evaluated as True.

    Arguments:
        - timeout: int, timeout in seconds.
        - func: function that need to return True or False.
        - args, kwargs: arguments to function.

    Returns:
        - result of function execution.
    """
    result = func(*args, **kwargs)

    timestamp_end = time.time() + timeout
    while timestamp_end > time.time():
        time.sleep(0.5)
        result = func(*args, **kwargs)
        if result:
            break
    return result
