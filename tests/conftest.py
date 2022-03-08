"""pytest plugin configuration.

https://docs.pytest.org/en/latest/writing_plugins.html#conftest-py-plugins
"""

import pytest


@pytest.fixture
def match_list():
    """Return list of matched username, password, and hashes."""
    return [
        {
            "user": "domain1.local\\Bill",
            "hash": "d739c6021d574f5f19822feecae9db15",
            "password": "p@ssword",
        },
        {
            "user": "domain1.local\\Jane",
            "hash": "4c604a4431bf49c1bdcd3b1f458efdd4",
            "password": "doe",
        },
        {
            "user": "domain1.local/John",
            "hash": "4c604a4431bf49c1bdcd3b1f458efdd4",
            "password": "doe",
        },
        {
            "user": "domain2.local\\Frank",
            "hash": "50f57adca07aca56d165aaf2d958e03c",
            "password": "YellowFin32!",
        },
        {
            "user": "domain2.local\\Jill",
            "hash": "dc35d01a6d8140dd5bf978ea3ab7c3d2",
            "password": "Wash3r",
        },
        {
            "user": "domain2.local\\Mike",
            "hash": "d739c6021d574f5f19822feecae9db15",
            "password": "p@ssword",
        },
        {
            "user": "domain1.local\\John",
            "hash": "d739c6021d574f5f19822feecae9db15",
            "password": "p@ssword",
        },
        {
            "user": "domain1.local\\Sam",
            "hash": "d739c6021d574f5f19822feecae9db15",
            "password": "p@ssword",
        },
        {
            "user": "domain2.local\\You",
            "hash": "c8137e7842466aa292c143a9be887755",
            "password": "",
        },
        {
            "user": "domain1.local\\Charlie",
            "hash": "fa19f8748a9b52a1138470b446969633",
            "password": "YankyRoad1@",
        },
        {
            "user": "domain1.local\\admin",
            "hash": "21232f297a57a5a743894a0e4a801fc3",
            "password": "admin",
        },
    ]


@pytest.fixture
def example_output_list():
    """Return list of matched username, password, and hashes."""
    return [
        "|Complexity|Count|",
        "|--|--|",
        "|1|2|",
        "|2|1|",
        "|3|1|",
        "|4|2|",
        "<br>The top 5 passwords:",
        "",
        "|Count|Password|",
        "|--|--|",
        "|4|p@ssword|",
        "|2|doe|",
        "|1|YellowFin32!|",
        "|1|Wash3r|",
        "|1|YankyRoad1@|",
        "<br>The password lengths:",
        "",
        "|Length|Count|",
        "|--|--|",
        "|3|2|",
        "|5|1|",
        "|6|1|",
        "|8|4|",
        "|11|1|",
        "|12|1|",
    ]
