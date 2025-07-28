"""
Unit tests for the `utils.heuristic` module.
"""

# Imports
import os
import sys


# Paths
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
parent_dir = os.path.dirname(self_dir)
sys.path.append(parent_dir)
from utils.heuristic import compare_policies, contains_policy


### TEST VARIABLES ###

policy_a = {
    "bidirectional": True,
    "protocols": {
        "ipv4": {
            "src": "self",
            "dst": "192.168.1.110"
        },
        "tcp": {
            "dst-port": 9999
        }
    }
}

policy_b = {
    "bidirectional": True,
    "protocols": {
        "ipv4": {
            "src": "self",
            "dst": "192.168.1.110"
        },
        "tcp": {
            "dst-port": 9999
        }
    }
}

policy_c = {
    "bidirectional": True,
    "protocols": {
        "ipv4": {
            "src": "192.168.1.110",
            "dst": "self"
        },
        "tcp": {
            "src-port": 9999
        }
    }
}

policy_d = {
    "bidirectional": True,
    "protocols": {
        "ipv4": {
            "src": "192.168.1.110",
            "dst": "self"
        },
        "tcp": {
            "dst-port": 9999
        }
    }
}

policy_e = {
    "bidirectional": True,
    "protocols": {
        "ipv4": {
            "src": "self",
            "dst": "192.168.1.110"
        },
        "tcp": {
            "dst-port": 9999
        },
        "http": {
            "method": "GET"
        }
    }
}


### TEST FUNCTIONS ###


## Policies

def test_compare_policies() -> None:
    """
    Unit test for the function `compare_policies`,
    which checks if two policies are equal.
    """
    assert compare_policies(policy_a, policy_b)
    assert compare_policies(policy_a, policy_c)
    assert not compare_policies(policy_a, policy_d)
    assert not compare_policies(policy_a, policy_e)


def test_contains_policy() -> None:
    """
    Unit test for the function `contains_policy`,
    which checks if a list of policies contains a given policy
    """
    policies = [policy_a]
    assert contains_policy(policies, policy_a)
    assert contains_policy(policies, policy_b)
    assert contains_policy(policies, policy_c)
    assert not contains_policy(policies, policy_d)
    assert not contains_policy(policies, policy_e)
