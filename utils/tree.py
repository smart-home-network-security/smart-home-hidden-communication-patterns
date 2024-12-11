"""
Utility functions to handle tree structures.
"""

from typing import Any
import os
import json
from treelib import Tree

import logging
logger_name = os.path.basename(__name__)
logger = logging.getLogger(logger_name)


def init_empty_tree() -> Tree:
    """
    Initialize an empty tree structure.

    Returns:
        treelib.Tree: empty tree
    """
    tree = Tree()
    id = "0_root"
    tree.create_node(id, id, data=(0, []))
    return tree


def build_tree(tree: Tree, tree_data: dict, parent: str = None) -> Tree:
    """
    Recursive-terminal function to build a tree structure.

    Args:
        tree (treelib.Tree): current tree structure
        tree_data (dict): tree data from the JSON file
        parent (str): parent node identifier
    Returns:
        treelib.Tree: final tree structure
    """
    if not tree_data:
        # No more nodes to add
        return tree
    
    # Get node data
    name = list(tree_data.keys())[0]
    data = tree_data[name].get("data", (0, []))

    # Add node to tree
    if parent is None:
        # Root node
        tree.create_node(name, name, data=data)
    else:
        # Generic node
        tree.create_node(name, name, data=data, parent=parent)
    
    # Recursively add children
    for child in tree_data[name].get("children", []):
        build_tree(tree, child, name)

    return tree


def load_from_json(tree_file_path: str) -> Tree:
    """
    Load a tree from a file.

    Args:
        tree_file_path (str): path to the tree file
    Returns:
        treelib.Tree: loaded tree
    """
    # Read tree from JSON
    tree_json = {}
    with open(tree_file_path, "r") as f:
        tree_json = json.load(f)
    
    # Create tree structure
    return build_tree(Tree(), tree_json)


def display_tree(tree: Tree, policy_name: str = None) -> None:
    """
    Display the tree structure in the console,
    with the given policy highlighted in green.

    Args:
        tree (treelib.Tree): Tree structure to display
        policy_name (str): Name of the policy to highlight. If None, no policy is highlighted.
    """
    # Generate current tree
    tree_str = tree.show(stdout=False)

    # Highlight given policy in green
    if policy_name:
        green_start = "\033[32m"  # Start green text
        color_reset = "\033[0m"   # Reset to default color
        tree_str = tree_str.replace(policy_name, f"{green_start}{policy_name}{color_reset}")

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


def save_to_json(tree: Tree, json_path: str, last_policy_name: str = None) -> None:
    """
    Save the given tree structure to a JSON file.

    Args:
        tree (treelib.Tree): tree structure to save
        json_path (str): path to the JSON file
        last_policy_name (str): name of the last processed policy
    """
    # Generate JSON tree
    tree_str = tree.to_json(with_data=True)
    tree_json = json.loads(tree_str)

    # Indicate last policy in the tree
    if last_policy_name:
        try:
            last_node = find_key_in_dict(tree_json, last_policy_name)
            last_node["last"] = True
        except KeyError as e:
            logger.warning(e)
            logger.warning("Not indicating last policy in JSON tree.")

    with open(json_path, "w") as f:
        json.dump(tree_json, f, indent=2)


def find_last_policy(d: Any, parent_key: str = "") -> str:
    """
    Recursively search the given dictionary for the last processed policy,
    i.e. the one having the `last` key set to `True`.

    Args:
        d (Any): dictionary to search, or any of its elements
        parent_name (str): key of the parent node
    Returns:
        str: name of the last processed policy
    Raises:
        KeyError: if no policy is marked as the last one
    """
    # Reached a leaf node
    if not (isinstance(d, dict) or isinstance(d, list)):
        raise KeyError("No policy is marked as the last one in the dictionary")
    
    if isinstance(d, dict):
        try:
            # Found last policy, return its name
            if d["last"]:
                return parent_key
        except KeyError:
            for k, v in d.items():
                try:
                    # Last policy not found in this sub-dictionary,
                    # search recursively
                    return find_last_policy(v, k)
                except KeyError:
                    # Last policy not found in this leg of the dictionary,
                    # continue iterating on keys
                    continue
    
    elif isinstance(d, list):
        for i, v in enumerate(d):
            try:
                # Iterate over list elements
                return find_last_policy(v, f"{parent_key}[{i}]")
            except KeyError:
                # Last policy not found in this leg of the dictionary,
                # continue iterating on keys
                continue

    raise KeyError("No policy is marked as the last one in the dictionary")
