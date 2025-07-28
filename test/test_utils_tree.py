"""
Unit tests for the `utils.tree.py` module.
"""

# Imports
import os
import sys
from pathlib import Path
import json
from treelib import Tree
import pytest

# Paths
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
parent_dir = os.path.dirname(self_dir)
sys.path.append(parent_dir)
import utils.tree as tree_utils


### TEST VARIABLES ###

tree_data = {
    "root": {
        "data": "root",
        "children": [
            {"node1": {"data": "node1", "children": [
                {"node1.1": {"data": "node1.1"}},
                {"node1.2": {"data": "node1.2"}}
            ]}},
            {"node2": {"data": "node2"}}
        ]
    }
}

tree_data_with_last = {
    "root": {
        "data": "root",
        "children": [
            {"node1": {"data": "node1", "children": [
                {"node1.1": {"data": "node1.1"}},
                {"node1.2": {"data": "node1.2", "last": True}}
            ]}},
            {"node2": {"data": "node2"}}
        ]
    }
}


def test_init_empty_tree() -> None:
    """
    Unit test for the function `init_empty_tree`,
    which initializes an empty tree.
    """
    tree = tree_utils.init_empty_tree()
    id = "0_root"
    data_empty = {"depth": 0, "flows": []}
    assert isinstance(tree, Tree)
    assert tree.get_node(id) is not None
    assert tree.get_node(id).data == data_empty


def test_build_tree() -> None:
    """
    Unit test for the function `build_tree`,
    which builds a tree from a dictionary.
    """
    tree = tree_utils.build_tree(Tree(), tree_data)
    assert isinstance(tree, Tree)
    assert tree.get_node("root") is not None
    assert tree.get_node("root").data == "root"
    assert tree.get_node("node1") is not None
    assert tree.get_node("node1").data == "node1"
    assert tree.get_node("node1.1") is not None
    assert tree.get_node("node1.1").data == "node1.1"
    assert tree.get_node("node1.2") is not None
    assert tree.get_node("node1.2").data == "node1.2"
    assert tree.get_node("node2") is not None
    assert tree.get_node("node2").data == "node2"


def test_load_from_json() -> None:
    """
    Unit test for the function `load_from_json`,
    which loads a tree from a JSON file.
    """
    tree_json_path = os.path.join(self_dir, "tree.json")

    tree = tree_utils.load_from_json(tree_json_path)
    assert isinstance(tree, Tree)
    assert tree.get_node("root") is not None
    assert tree.get_node("root").data == "root"
    assert tree.get_node("node1") is not None
    assert tree.get_node("node1").data == "node1"
    assert tree.get_node("node1.1") is not None
    assert tree.get_node("node1.1").data == "node1.1"
    assert tree.get_node("node1.2") is not None
    assert tree.get_node("node1.2").data == "node1.2"
    assert tree.get_node("node2") is not None
    assert tree.get_node("node2").data == "node2"


def test_save_to_txt(tmp_path: Path) -> None:
    """
    Unit test for the function `save_to_txt`,
    which saves a tree to a TXT file.

    Args:
        tmp_path (Path): path to a temporary directory
    """
    tree = tree_utils.build_tree(Tree(), tree_data)
    tree_txt_path = os.path.join(tmp_path, "tree.txt")

    tree_utils.save_to_txt(tree, tree_txt_path)
    assert os.path.exists(tree_txt_path)


def test_find_key_in_dict() -> None:
    """
    Unit test for the function `find_key_in_dict`,
    which finds a key in a dictionary.
    """
    # Node 1.1
    expected = {"data": "node1.1"}
    actual = tree_utils.find_key_in_dict(tree_data, "node1.1")
    assert actual == expected

    # Node 1.2
    expected = {"data": "node1.2"}
    actual = tree_utils.find_key_in_dict(tree_data, "node1.2")
    assert actual == expected

    # Node 2
    expected = {"data": "node2"}
    actual = tree_utils.find_key_in_dict(tree_data, "node2")
    assert actual == expected

    # Unknown key
    with pytest.raises(KeyError):
        tree_utils.find_key_in_dict(tree_data, "node3")


def test_save_to_json(tmp_path: Path) -> None:
    """
    Unit test for the function `save_to_json`,
    which saves a tree to a JSON file.

    Args:
        tmp_path (Path): path to a temporary directory
    """
    tree = tree_utils.build_tree(Tree(), tree_data)
    tree_json_path = os.path.join(tmp_path, "tree.json")

    # Do not indicate last policy
    tree_utils.save_to_json(tree, tree_json_path)
    assert os.path.exists(tree_json_path)
    with open(tree_json_path, "r") as f:
        json.load(f)

    # Indicate last policy
    tree_utils.save_to_json(tree, tree_json_path, last_id="node1.2")
    assert os.path.exists(tree_json_path)
    with open(tree_json_path, "r") as f:
        json.load(f)


def test_find_last_node() -> None:
    """
    Unit test for the function `find_last_node`,
    which finds the last policy in a tree dictionary.
    """
    # With last policy
    expected = "node1.2"
    actual = tree_utils.find_last_node(tree_data_with_last)
    assert actual == expected

    # Without last policy
    with pytest.raises(KeyError):
        tree_utils.find_last_node(tree_data)
