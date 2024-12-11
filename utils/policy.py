from typing import Union, Tuple, Iterator
from treelib import Tree


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
    for node in tree.all_nodes():
        # node.data := (depth, policy_list)
        # Comparison must be applied to the last policy in the list
        policy_list = node.data[1]
        if len(policy_list) > 0 and compare_policies(policy_list[-1], policy):
            return True
    
    return False
