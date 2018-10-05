"""
This file contains utils for fast specify platform.
"""

import platform as p

_author_ = "anton.ohontsev@gmail.com"

OS_WIN = ('Windows', )
OS_WIN_7 = OS_WIN + ('7', )
OS_WIN_8 = OS_WIN + ('8', )
OS_WIN_8_1 = OS_WIN + ('8.1', )
OS_WIN_10 = OS_WIN + ('10', )
OS_WIN_xp = OS_WIN + ('XP', )

OS_MAC = ('Darwin', )

OS_LINUX = ('Linux', )

OS_ANY = OS_UNKNOWN = ()


def get_current_platform():
    """Gets current platform.

    Arguments:
        - None

    Return:
        - Tuple of (Platform name, release name, processor architecture).
    """
    bits = '{}bit'.format(64 if '64' in p.machine() else 32)
    return p.system(), p.release(), bits


def is_(platform):
    """Compares platforms.

    Arguments:
        - platform: tuple, tuple with:
            1. Platform name
            2. Release name
            3. Processor architecture (not necessary)

    Return:
        - Bool flag that indicates result of the comparison.
    """
    return get_current_platform()[:len(platform)] == platform
