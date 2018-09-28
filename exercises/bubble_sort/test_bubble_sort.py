"""
This file contains unit-tests for bubble sort algorithm.
"""

_author_ = "anton.ohontsev@gmail.com"

import random
import sys
import unittest

from exercises.bubble_sort import bubble_sort


class TestBubbleSort(unittest.TestCase):
    def test_empty_array(self):
        self.assertEqual([], bubble_sort.sort([]))

    def test_single_size_array(self):
        self.assertEqual([0], bubble_sort.sort([0]),
                         "single size array not changed after sorting")

    def test_simple_array(self):
        self.assertEqual([1, 2, 3, 4, 5, 6, 7, 8],
                         bubble_sort.sort([6, 5, 3, 1, 8, 7, 2, 4]),
                         "array sorted correctly")

    def test_huge_array(self):
        array = random.sample(range(1, sys.maxsize), 1000)
        result = bubble_sort.sort(array)
        self.assertEqual(sorted(array), result, "array sorted correctly")

    def test_array_with_negatives(self):
        array = [-10, -9, -2, -1, -6, -5, -4, -3, -8, -7]
        result = bubble_sort.sort(array)
        self.assertEqual(sorted(array), result, "array sorted correctly")
