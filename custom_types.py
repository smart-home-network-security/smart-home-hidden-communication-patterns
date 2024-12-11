import re


def mac_address(val: str) -> str:
    """
    Argparse type which validates a MAC address.

    Args:
        val (str): The MAC address to validate.
    Returns:
        str: The given MAC address if valid.
    Raises:
        ValueError: If the given MAC address is invalid.
    """
    mac_regex = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    if not re.match(mac_regex, val):
        raise ValueError(f"Invalid MAC address: {val}")
    return val


def ip_address(val: str) -> str:
    """
    Argparse type which validates an IPv4 address.

    Args:
        val (str): The IPv4 address to validate.
    Returns:
        str: The given IPv4 address if valid.
    Raises:
        ValueError: If the given IP address is invalid.
    """
    ip_regex = r'\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
    if not re.match(ip_regex, val):
        raise ValueError(f"Invalid IPv4 address: {val}")
    return val
