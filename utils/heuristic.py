from typing import Union, Tuple, Iterator
from treelib import Tree, Node
from signature_extraction.network import FlowFingerprint


##### UTILS #####

def get_node_depth(node: Node) -> int:
    """
    Get a tree node's depth.

    Args:
        node (treelib.Node): given node
    Returns:
        int: Depth of the node.
    """
    if isinstance(node.data, tuple) or isinstance(node.data, list):
        return node.data[0]
    elif isinstance(node.data, dict):
        return node.data.get("depth", 0)


def get_node_flows(node: Node) -> list:
    """
    Get a tree node's list of flows.

    Args:
        node (treelib.Node): given node
    Returns:
        list: list of flows associated with the node.
    """
    if isinstance(node.data, tuple) or isinstance(node.data, list):
        return node.data[1]
    elif isinstance(node.data, dict):
        return node.data.get("flows", [])



##### POLICIES (DICTS) #####

def compare_policies(policy_a: dict, policy_b: dict) -> bool:
    """
    Check if two policy dictionaries represent the same policy,
    without considering traffic direction.

    Args:
        policy_a (dict): first policy dictionary
        policy_b (dict): second policy dictionary
    Returns:
        bool: True if policies are equal, False otherwise
    """
    is_bidirectional = policy_a.get("bidirectional", False) or policy_b.get("bidirectional", False)
    policy_a = policy_a.get("protocols", {})
    policy_b = policy_b.get("protocols", {})

    # Policies are not bidirectional
    # Protocol fields must be identical
    if not is_bidirectional:
        return policy_a == policy_b
    
    # One of the policies is bidirectional

    # Check if policies have the same set of protocols
    if policy_a.keys() != policy_b.keys():
        return False

    # Check if policies have the same rules for each protocol
    same_direction = False

    ## IP hosts
    ip_proto = ""
    if "ipv4" in policy_a and "ipv4" in policy_b:
        ip_proto = "ipv4"
    elif "ipv6" in policy_a and "ipv6" in policy_b:
        ip_proto = "ipv6"

    if ip_proto == "ipv4" or ip_proto == "ipv6":
        fields_a = policy_a[ip_proto]
        fields_b = policy_b[ip_proto]
        if "src" in fields_a:
            if "src" in fields_b and fields_a["src"] == fields_b["src"]:
                same_direction = True
            elif "dst" in fields_b and fields_a["src"] == fields_b["dst"]:
                same_direction = False
            else:
                return False
        if "dst" in fields_a:
            if "src" in fields_b and fields_a["dst"] == fields_b["src"]:
                same_direction = False
            elif "dst" in fields_b and fields_a["dst"] == fields_b["dst"]:
                same_direction = True
            else:
                return False

    ## Transport protocol
    transport_proto = ""
    if "tcp" in policy_a and "tcp" in policy_b:
        transport_proto = "tcp"
    elif "udp" in policy_a and "udp" in policy_b:
        transport_proto = "udp"

    if transport_proto == "tcp" or transport_proto == "udp":
        fields_a = policy_a[transport_proto]
        fields_b = policy_b[transport_proto]
        if "src-port" in fields_a:
            if same_direction:
                if "src-port" not in fields_b:
                    return False
                elif "src-port" in fields_b and fields_a["src-port"] != fields_b["src-port"]:
                    return False
            elif not same_direction:
                if "dst-port" not in fields_b:
                    return False
                elif "dst-port" in fields_b and fields_a["src-port"] != fields_b["dst-port"]:
                    return False
        if "dst-port" in fields_a:
            if same_direction:
                if "dst-port" not in fields_b:
                    return False
                elif "dst-port" in fields_b and fields_a["dst-port"] != fields_b["dst-port"]:
                    return False
            elif not same_direction:
                if "src-port" not in fields_b:
                    return False
                elif "src-port" in fields_b and fields_a["dst-port"] != fields_b["src-port"]:
                    return False
    
    ## Other protocols
    other_protocols = set(policy_a.keys()) - {"ipv4", "ipv6", "tcp", "udp"}
    for protocol in other_protocols:
        if protocol not in policy_b:
            # Policies do not have the same set of protocols
            return False
        elif policy_a[protocol] != policy_b[protocol]:
            # Policies have different rules for the same protocol
            return False

    return True


def contains_policy(policies: Iterator[Union[Tuple[str, dict], dict]], policy: dict) -> bool:
    """
    Check if a policy is contained in a policies iterator.

    Args:
        policies (Iterator[Union[Tuple[str, dict], dict]]): iterator over policies (name and policy dict, or policy dict only)
        policy (dict): policy dictionary to search for
    Returns:
        bool: True if policy is contained, False otherwise
    """
    for p in policies:
        if isinstance(p, tuple):
            p = p[1]
        if compare_policies(p, policy):
            return True
    return False


def tree_contains_policy(policy: Union[Tuple[str, dict], dict], tree: Tree) -> bool:
    """
    Check if a given policy is already present in the tree.

    Args:
        policy (Union[Tuple[str, dict], dict]): policy to check
        tree (treelib.Tree): tree structure to search in
    Returns:
        bool: True if policy is present in the tree, False otherwise
    """
    # Get only policy dictionary
    if isinstance(policy, tuple):
        policy = policy[1]

    # Iterate over all tree nodes
    for node in tree.all_nodes_itr():
        # node.data := (depth, policy_list) | {"depth": int, "flows": list[FlowFingerprint]}
        # Comparison must be applied to the last policy in the list
        policy_list = get_node_flows(node)
        if len(policy_list) > 0 and compare_policies(policy_list[-1], policy):
            return True
    
    return False


def compare_list_policies(list_policies_a: list, list_policies_b: list) -> bool:
    """
    Check if two lists of policies strictly contain equivalent policies.

    Args:
        list_policies_a (list): first list of policies
        list_policies_b (list): second list of policies
    Returns:
        bool: True if lists strictly contain equivalent policies, False otherwise
    """
    # If lists do not contain the same number of policies, they are not equivalent
    if len(list_policies_a) != len(list_policies_b):
        return False
    
    # Check if all policies in list_a are equivalent to policies in list_b
    for policy_a in list_policies_a:
        if not contains_policy(list_policies_b, policy_a):
            return False
    
    return True


def contains_list_policies(list_of_list_policies: list, policies: list) -> bool:
    """
    Check if a list of policies is contained in a list of lists of policies.

    Args:
        list_of_list_policies (list): list of lists of policies
        policies (list): list of policies to search for
    Returns:
        bool: True if policies is contained in list_of_list_policies, False otherwise
    """
    for l in list_of_list_policies:
        if compare_list_policies(l, policies):
            return True
    
    return False



##### FLOW FINGERPRINTS #####


def list_contains_flow(
        flow: FlowFingerprint,
        list_flows: list[FlowFingerprint],
        match_random_ports: bool = False
    ) -> bool:
    """
    Check if a given FlowFingerprint is present in the list of FlowFingerprints.

    Args:
        flow (FlowFingerprint): FlowFingerprint to search for
        list_flows (list[FlowFingerprint]): list of FlowFingerprints to search in
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        bool: True if FlowFingerprint is present in the list, False otherwise
    """
    for f in list_flows:
        if f.match_flow(flow, match_random_ports):
            return True
    
    return False


def path_contains_flow(
        flow: FlowFingerprint,
        node: Node,
        match_random_ports: bool = False
    ) -> bool:
    """
    Check if a given FlowFingerprint is present in the path from the given node to the tree root.

    Args:
        flow (FlowFingerprint): FlowFingerprint to search for
        node (treelib.Node): node to start searching from
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        bool: True if FlowFingerprint is present in the path, False otherwise
    """
    path = get_node_flows(node)[:-1]  # Get the list of flows from the node, excluding the node itself
    return list_contains_flow(flow, path, match_random_ports)


def tree_contains_flow(flow: FlowFingerprint, tree: Tree, match_random_ports: bool = False) -> bool:
    """
    Check if a given FlowFingerprint is already present in the tree.

    Args:
        flow (FlowFingerprint): FlowFingerprint to check
        tree (treelib.Tree): tree structure to search in
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        bool: True if FlowFingerprint is present in the tree, False otherwise
    """
    # Iterate over all tree nodes
    for node in tree.all_nodes_itr():
        # node.data := {"depth": int, "flows": list[FlowFingerprint]}
        # Comparison must be applied to the last policy in the list
        list_flows: list[FlowFingerprint] = get_node_flows(node)
        if len(list_flows) > 0 and list_flows[-1].match_flow(flow, match_random_ports):
            return True
    
    return False


def compare_list_flows(
        list_flows_a: list[FlowFingerprint],
        list_flows_b: list[FlowFingerprint],
        match_random_ports: bool = False
    ) -> bool:
    """
    Check if two lists of FlowFingerprints strictly contain equivalent FlowFingerprints.

    Args:
        list_flows_a (list[FlowFingerprint]): first list of FlowFingerprints
        list_flows_b (list[FlowFingerprint]): second list of FlowFingerprints
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        bool: True if lists strictly contain equivalent FlowFingerprints, False otherwise
    """
    # If lists do not contain the same number of FlowFingerprints, they are not equivalent
    if len(list_flows_a) != len(list_flows_b):
        return False
    
    # Check if all FlowFingerprints in list_a are equivalent to FlowFingerprints in list_b
    for flow_a in list_flows_a:
        if not flow_a.match_flow(list_flows_b, match_random_ports):
            return False
    
    return True


def list_contains_path_flows(
        list_paths: list[list[FlowFingerprint]],
        path_flows: list[FlowFingerprint],
        match_random_ports: bool = False
    ) -> bool:
    """
    Check if a list of FlowFingerprints is contained in a list of lists of FlowFingerprints.

    Args:
        list_paths (list[list[FlowFingerprint]]): list of lists of FlowFingerprints
        path_flows (list[FlowFingerprint]): list of FlowFingerprints to search for
        match_random_ports (bool): Whether to consider random ports in flow matching.
                                   Optional, default is False.
    Returns:
        bool: True if path_flows is contained in list_paths, False otherwise
    """
    for path in list_paths:
        if compare_list_flows(path, path_flows, match_random_ports):
            return True
    
    return False
