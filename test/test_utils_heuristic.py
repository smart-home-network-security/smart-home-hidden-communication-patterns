"""
Unit tests for the `utils.heuristic` module.
"""

# Imports
import os
import sys
from signature_extraction import FlowFingerprint


# Paths
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
parent_dir = os.path.dirname(self_dir)
sys.path.append(parent_dir)
from utils.tree import init_empty_tree
from utils.heuristic import (
    # Policies
    compare_policies,
    contains_policy,
    tree_contains_policy,
    compare_list_policies,
    contains_list_policies,
    # FlowFingerprints
    list_contains_flow,
    path_contains_flow,
    tree_contains_flow,
    compare_list_flows,
    list_contains_path_flows
)


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
flow_a = FlowFingerprint.from_policy(policy_a)

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
flow_b = FlowFingerprint.from_policy(policy_b)

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
flow_c = FlowFingerprint.from_policy(policy_c)

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
flow_d = FlowFingerprint.from_policy(policy_d)

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
flow_e = FlowFingerprint.from_policy(policy_e)


## Tree containing policies
tree_policies = init_empty_tree()
tree_policies.create_node("1_policy_a", "1_policy_a", parent="0_root", data={"depth": 1, "flows": [policy_a]})
tree_policies.create_node("2_policy_d", "2_policy_d", parent="1_policy_a", data={"depth": 2, "flows": [policy_a, policy_d]})

## Tree containing FlowFingerprint objects
tree_flows = init_empty_tree()
tree_flows.create_node("1_flow_a", "1_flow_a", parent="0_root", data={"depth": 1, "flows": [flow_a]})
tree_flows.create_node("2_flow_d", "2_flow_d", parent="1_flow_a", data={"depth": 2, "flows": [flow_a, flow_d]})


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


def test_tree_contains_policy() -> None:
    """
    Unit test for the function `tree_contains_policy`,
    which checks if a tree contains a given policy.
    """
    assert tree_contains_policy(tree_policies, policy_a)
    assert tree_contains_policy(tree_policies, policy_b)
    assert tree_contains_policy(tree_policies, policy_c)
    assert tree_contains_policy(tree_policies, policy_d)
    assert not tree_contains_policy(tree_policies, policy_e)


def test_compare_list_policies() -> None:
    """
    Unit test for the function `compare_list_policies`,
    which checks if two lists of policies are equal.
    """
    policies_a = [policy_a]
    policies_b = [policy_b]
    policies_c = [policy_c]
    policies_d = [policy_d]
    policies_e = [policy_e]
    policies_ad = [policy_a, policy_d]
    policies_ae = [policy_a, policy_e]

    assert compare_list_policies(policies_a, policies_b)
    assert compare_list_policies(policies_a, policies_c)
    assert not compare_list_policies(policies_a, policies_d)
    assert not compare_list_policies(policies_a, policies_e)
    assert not compare_list_policies(policies_a, policies_ad)
    assert not compare_list_policies(policies_a, policies_ae)
    assert not compare_list_policies(policies_ad, policies_ae)


def contains_list_policies() -> None:
    """
    Unit test for the function `contains_list_policies`,
    which checks if a list of policies is contained in a list of lists of policies.
    """
    policies_a = [policy_a]
    policies_b = [policy_b]
    policies_c = [policy_c]
    policies_d = [policy_d]
    policies_e = [policy_e]
    policies_all = [policies_a, policies_d]
    
    assert contains_list_policies(policies_all, policies_a)
    assert contains_list_policies(policies_all, policies_b)
    assert contains_list_policies(policies_all, policies_c)
    assert contains_list_policies(policies_all, policies_d)
    assert not contains_list_policies(policies_all, policies_e)


## Flow Fingerprints

def test_list_contains_flow() -> None:
    """
    Unit test for the function `list_contains_flow`,
    which checks if a list of FlowFingerprints contains a given FlowFingerprint.
    """
    flows_a = [flow_a]
    flows_d = [flow_d]
    flows_e = [flow_e]

    assert list_contains_flow(flows_a, flow_a)
    assert list_contains_flow(flows_a, flow_b)
    assert list_contains_flow(flows_a, flow_c)
    assert list_contains_flow(flows_d, flow_d)
    assert not list_contains_flow(flows_d, flow_a)
    assert list_contains_flow(flows_e, flow_e)
    assert not list_contains_flow(flows_e, flow_a)


def test_path_contains_flow() -> None:
    """
    Unit test for the function `path_contains_flow`,
    which checks if a given FlowFingerprint
    is present in the tree path from the given node to the root.
    """
    node_d = tree_flows.get_node("2_flow_d")
    assert path_contains_flow(node_d, flow_a)
    assert path_contains_flow(node_d, flow_b)
    assert path_contains_flow(node_d, flow_c)
    assert not path_contains_flow(node_d, flow_d)
    assert not path_contains_flow(node_d, flow_e)


def test_tree_contains_flow() -> None:
    """
    Unit test for the function `tree_contains_flow`,
    which checks if a given tree contains a given FlowFingerprint.
    """
    assert tree_contains_flow(tree_flows, flow_a)
    assert tree_contains_flow(tree_flows, flow_b)
    assert tree_contains_flow(tree_flows, flow_c)
    assert tree_contains_flow(tree_flows, flow_d)
    assert not tree_contains_flow(tree_flows, flow_e)


def test_compare_list_flows() -> None:
    """
    Unit test for the function `compare_list_flows`,
    which checks if two lists of FlowFingerprints are strictly equivalent.
    """
    flows_a = [flow_a]
    flows_b = [flow_b]
    flows_c = [flow_c]
    flows_d = [flow_d]
    flows_e = [flow_e]
    flows_ad = [flow_a, flow_d]
    flows_ae = [flow_a, flow_e]

    assert compare_list_flows(flows_a, flows_b)
    assert compare_list_flows(flows_a, flows_c)
    assert not compare_list_flows(flows_a, flows_d)
    assert not compare_list_flows(flows_a, flows_e)
    assert not compare_list_flows(flows_a, flows_ad)
    assert not compare_list_flows(flows_a, flows_ae)
    assert not compare_list_flows(flows_ad, flows_ae)


def test_list_contains_path_flows() -> None:
    """
    Unit test for the function `list_contains_path_flows`,
    which checks if a list of FlowFingerprints is contained in a list of lists of FlowFingerprints.
    """
    flows_a = [flow_a]
    flows_b = [flow_b]
    flows_c = [flow_c]
    flows_d = [flow_d]
    flows_e = [flow_e]
    flows_all = [flows_a, flows_d]

    assert list_contains_path_flows(flows_all, flows_a)
    assert list_contains_path_flows(flows_all, flows_b)
    assert list_contains_path_flows(flows_all, flows_c)
    assert list_contains_path_flows(flows_all, flows_d)
    assert not list_contains_path_flows(flows_all, flows_e)
