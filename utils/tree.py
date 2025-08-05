"""
Utility functions to handle tree structures.
"""

from typing import Any
import os
import json
from ipaddress import IPv4Address
from treelib import Tree, Node
from signature_extraction.network import FlowFingerprint

import logging
logger_name = os.path.basename(__name__)
logger = logging.getLogger(logger_name)


class CustomJsonEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle the serialization of objects contained in the tree,
    i.e. FlowFingerprint objects.
    """

    def __init__(self, ipv4: IPv4Address, *args, **kwargs) -> None:
        """
        Constructor.
        Provides the IPv4 address of the device to the JSON encoder.
        """
        super().__init__(*args, **kwargs)
        self.ipv4 = ipv4


    def default(self, obj):
        """
        Override the default method to handle custom objects.
        """
        if isinstance(obj, FlowFingerprint):
            return obj.extract_policy(self.ipv4)
        else:
            # Call the base class method for other types
            return super().default(obj)


def init_empty_tree() -> Tree:
    """
    Initialize an empty tree structure.

    Returns:
        treelib.Tree: empty tree
    """
    tree = Tree()
    id = "0_root"
    data = {
        "depth": 0,
        "flows": []
    }
    tree.create_node(id, id, data=data)
    return tree


def build_tree(tree: Tree, tree_data: dict, parent: str = None, to_flows: bool = False) -> Tree:
    """
    Recursive-terminal function to build a tree structure.

    Args:
        tree (treelib.Tree): current tree structure
        tree_data (dict): tree data from the JSON file
        parent (str): parent node identifier
        to_flows (bool): if True, convert node policies to FlowFingerprint objects
    Returns:
        treelib.Tree: final tree structure
    """
    if not tree_data:
        # No more nodes to add
        return tree
    
    # Get node data
    name = list(tree_data.keys())[0]
    data_default = {
        "depth": 0,
        "flows": []
    }
    data = tree_data[name].get("data", data_default)

    # Convert node policies to FlowFingerprint objects if required
    if to_flows:
        if "flows" in data:
            # Convert flows to FlowFingerprint objects
            data["flows"] = [FlowFingerprint.from_policy(flow) for flow in data["flows"]]
        else:
            # Initialize empty flows list
            data["flows"] = []

    # Add node to tree
    if parent is None:
        # Root node
        tree.create_node(name, name, data=data)
    else:
        # Generic node
        tree.create_node(name, name, data=data, parent=parent)
    
    # Recursively add children
    for child in tree_data[name].get("children", []):
        build_tree(tree, child, name, to_flows)

    return tree


def load_from_json(tree_file_path: str, to_flows: bool = False) -> Tree:
    """
    Load a tree from a file.

    Args:
        tree_file_path (str): path to the tree file
        to_flows (bool): if True, convert node policies to FlowFingerprint objects
    Returns:
        treelib.Tree: loaded tree
    """
    # Read tree from JSON
    tree_json = {}
    with open(tree_file_path, "r") as f:
        tree_json = json.load(f)
    
    # Create tree structure
    return build_tree(Tree(), tree_json, to_flows=to_flows)


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


def display_tree(tree: Tree, id_highlight: str = None) -> None:
    """
    Display the tree structure in the console,
    with the given id highlighted in green.

    Args:
        tree (treelib.Tree): Tree structure to display
        id_highlight (str): id to highlight. If None, no id is highlighted.
    """
    # Generate current tree
    tree_str = tree.show(stdout=False)

    # Highlight given id in green
    if id_highlight:
        green_start = "\033[32m"  # Start green text
        color_reset = "\033[0m"   # Reset to default color
        tree_str = tree_str.replace(id_highlight, f"{green_start}{id_highlight}{color_reset}")

    # Write tree
    logger.info(tree_str)


def save_to_txt(tree: Tree, txt_path: str) -> None:
    """
    Save the given tree structure to a text file.

    Args:
        tree (treelib.Tree): tree structure to save
        txt_path (str): path to the text file
    """
    with open(txt_path, "w") as f:
        f.write(tree.show(stdout=False))


def find_key_in_dict(d: Any, key: str) -> Any:
    """
    Recursively search the given dictionary for the element with the given key.

    Args:
        d (Any): dictionary to search, or any of its elements
        key (str): key to search for
    Returns:
        Any: element with the given key
    Raises:
        KeyError: if the key is not found in the dictionary
    """
    # Reached a leaf node
    if not (isinstance(d, dict) or isinstance(d, list)):
        raise KeyError(f"Key '{key}' not found in dictionary")


    if isinstance(d, dict):
        # Key is present in the top-level dictionary
        if key in d:
            return d[key]
    
        # Iterate over children
        for _, v in d.items():
            try:
                # Found element, return it
                return find_key_in_dict(v, key)
            except KeyError:
                # Key not found in this sub-dictionary, continue iteration
                continue

    elif isinstance(d, list):
        # Iterate over list elements
        for e in d:
            try:
                # Found element, return it
                return find_key_in_dict(e, key)
            except KeyError:
                # Key not found in this list element, continue iteration
                continue

    raise KeyError(f"Key '{key}' not found in dictionary")


def save_to_json(tree: Tree, json_path: str, ip_device: str = None, last_id: str = None) -> None:
    """
    Save the given tree structure to a JSON file.

    Args:
        tree (treelib.Tree): tree structure to save
        ip_device (str): IP address of the device
        json_path (str): path to the JSON file
        last_id (str): last node id processed
    """
    # Generate JSON tree
    tree_dict = tree.to_dict(with_data=True)

    # Indicate last node in the tree
    if last_id:
        try:
            last_node = find_key_in_dict(tree_dict, last_id)
            last_node["last"] = True
        except KeyError as e:
            logger.warning(e)
            logger.warning("Not indicating last node id in JSON tree.")

    # Encode tree to JSON
    json_encoder = CustomJsonEncoder(ip_device, indent=2)
    json_str = json_encoder.encode(tree_dict)

    # Write JSON to file
    with open(json_path, "w") as f:
        f.write(json_str)


def find_last_node(d: Any, parent_key: str = "") -> str:
    """
    Recursively search the given dictionary for the last processed node,
    i.e. the one having the `last` key set to `True`.

    Args:
        d (Any): dictionary to search, or any of its elements
        parent_name (str): key of the parent node
    Returns:
        str: name of the last processed node
    Raises:
        KeyError: if no node is marked as the last one
    """
    # Reached a leaf node
    if not (isinstance(d, dict) or isinstance(d, list)):
        raise KeyError("No node is marked as the last one in the dictionary")
    
    if isinstance(d, dict):
        try:
            # Found last node, return its name
            if d["last"]:
                return parent_key
        except KeyError:
            for k, v in d.items():
                try:
                    # Last node not found in this sub-dictionary,
                    # search recursively
                    return find_last_node(v, k)
                except KeyError:
                    # Last node not found in this leg of the dictionary,
                    # continue iterating on keys
                    continue
    
    elif isinstance(d, list):
        for i, v in enumerate(d):
            try:
                # Iterate over list elements
                return find_last_node(v, f"{parent_key}[{i}]")
            except KeyError:
                # Last node not found in this leg of the dictionary,
                # continue iterating on keys
                continue

    raise KeyError("No node is marked as the last one in the dictionary")


def save_trees(tree: Tree, basename: str, ip_device: str = None, last_id: str = None) -> None:
    """
    Save the given tree structure to a text and JSON file.

    Args:
        tree (treelib.Tree): tree structure to save
        basename (str): base name of the files to save
        ip_device (str): IP address of the device
        last_id (str): last node id processed
    """
    # Save tree to text file
    save_to_txt(tree, f"{basename}.txt")
    # Save tree to JSON file
    save_to_json(tree, f"{basename}.json", ip_device, last_id)
