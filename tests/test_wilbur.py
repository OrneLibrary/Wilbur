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
    username_password_match,
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
        assert len(clean_empty_password(match_list)) == 10

    def test_get_password_length(self, match_list):
        """Test the get password length method."""
        assert get_password_length(match_list) == {8: 4, 3: 2, 12: 1, 6: 1, 11: 1, 5: 1}

    def test_password_reuse(self, match_list):
        """Test the password reuse method."""
        assert password_reuse(match_list, 5) == [
            ("p@ssword", 4),
            ("doe", 2),
            ("YellowFin32!", 1),
            ("Wash3r", 1),
            ("YankyRoad1@", 1),
        ]

    def test_password_complexity(self, match_list):
        """Test the password complexity method."""
        assert password_complexity(match_list) == {1: 2, 2: 1, 3: 1, 4: 2}

    def test_username_password_match(self, match_list):
        """Test the username password match method."""
        assert username_password_match(match_list) == [
            {
                "user": "admin",
                "hash": "21232f297a57a5a743894a0e4a801fc3",
                "password": "admin",
            },
        ]
