#!/usr/bin/env pytest -vs
"""Tests for Wilbur."""

# some_file.py
import sys

# insert at 1, 0 is the script path (or '' in REPL)
sys.path.append(".")

from wilbur import (
    clean_empty_password,
    get_password_length,
    password_complexity,
    password_reuse,
)


class TestWilbur:
    """Test the methods of Wilbur"""

    def test_clean_empty_password(self, match_list):
        """Test the clean empty password."""
        match_list.append(
            {
                "user": "You2",
                "hash": "c8137e7842466aa292c143a9be887755",
                "password": "",
            }
        )
        assert len(clean_empty_password(match_list)) == 9

    def test_get_password_length(self, match_list):
        """Test the get password length method."""
        assert get_password_length(match_list) == {8: 4, 3: 2, 12: 1, 6: 1, 11: 1}

    def test_password_reuse(self, match_list):
        """Test the password reuse method."""
        assert password_reuse(match_list, 5) == [
            ("<p@ssword> d739c6021d574f5f19822feecae9db15", 4),
            ("<doe> 4c604a4431bf49c1bdcd3b1f458efdd4", 2),
            ("<YellowFin32!> 50f57adca07aca56d165aaf2d958e03c", 1),
            ("<Wash3r> dc35d01a6d8140dd5bf978ea3ab7c3d2", 1),
            ("<YankyRoad1@> fa19f8748a9b52a1138470b446969633", 1),
        ]

    def test_password_complexity(self, match_list):
        """Test the password complexity method."""
        assert password_complexity(match_list) == {1: 1, 2: 1, 3: 1, 4: 2}