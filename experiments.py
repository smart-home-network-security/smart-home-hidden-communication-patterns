#!/usr/bin/python3

## Imports
# Libraries
from typing import Tuple, List, Any
from enum import Enum
import os
import glob
import time
import random
import logging
import argparse
import importlib
from copy import deepcopy
import subprocess
from fabric import Connection, Config
import json
import yaml
from treelib import Tree
from collections import deque
# Custom
from custom_types import mac_address, ip_address
from dns_unbound_cache_reader import read_dns_cache, update_dns_table
from profile_translator_blocklist import translate_policies
from signature_extraction.event_signature_extraction import pcaps_to_signature_pattern
from smart_home_testbed import init_device
import utils.tree as tree_utils
from utils.policy import tree_contains_policy


##### CONFIG #####

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NFTABLES_SCRIPT = "firewall.nft"
ROUTER_NFTABLES_SCRIPT = os.path.join("/", "tmp", NFTABLES_SCRIPT)
NFQUEUE_SRC = "nfqueues.c"
NFQUEUE_EXEC = "nfqueue"
ROUTER_NFQUEUE_EXEC = os.path.join("/", "tmp", NFQUEUE_EXEC)
# Logging
logger_name = os.path.basename(__name__)
logger = logging.getLogger(logger_name)

last_policy = None
is_app_on = False


class ConfigKeys(Enum):
    """
    Allowed keys in the configuration file.
    """
    # Device under test
    DEVICE = "device"
    NAME   = "name"
    MAC    = "mac"
    IPV4   = "ipv4"
    EVENT  = "event"
    ACCESS_POINT_INTERFACE = "access-point-interface"

    # Network gateway
    GATEWAY  = "gateway"
    HOSTNAME = "hostname"

    # Access point running the firewall
    ACCESS_POINT = "access-point"
    CONNECTED_TO = "connected-to"

    # Smartphone running the companion apps
    PHONE     = "phone"
    INTERFACE = "interface"

    # Experimental parameters
    EXP_PARAM    = "exp-param"
    N_EVENTS     = "n-events"
    PCAP_TIMEOUT = "pcap-timeout"
    WAIT_LOW     = "wait-low"
    WAIT_HIGH    = "wait-high"

    # Boot event's controllable plug(s)
    BOOT_PLUGS = "boot-plugs"

    # Other hosts to capture packets from
    OTHER_HOSTS = "other-hosts"

    # Hosts to filter out from the packet capture
    FILTER_HOSTS = "filter-hosts"



##### INITIAL SETUP #####

def is_connected(ip: str, interface: str = "") -> bool:
    """
    Test connection with the a host.

    Args:
        ip (str): host's IP address
        interface (str): interface to which the host is connected
    Returns:
        bool: True if host could be reached, False otherwise 
    """
    cmd = f"ping -w 5 -I {interface} {ip}"
    proc = subprocess.run(cmd.split(), capture_output=True)
    logger.info(str(proc.stdout.decode()))
    if proc.stderr:
        logger.warning(str(proc.stderr.decode()))
    return proc.returncode == 0


##### AUXILIARY FUNCTIONS #####

def start_traffic_capture(
        host: Connection,
        interface: str,
        output_file: str,
        device: Tuple[str, str] = None,
        other_hosts: List[dict] = [],
        filter_hosts: List[str] = []
    ) -> None:
    """
    Start traffic capture on the given host.

    Args:
        host (fabric.Connection): SSH connection to the host
        interface (str): interface on which to capture traffic
        output_file (str): file to the capture to
        device (Tuple[str, str]): device's MAC and IP addresses
        other_hosts (List[dict]): other hosts' IPv4 address(es) and interface(s) to capture traffic for
    """
    # Initialize traffic capture command for the device under test
    device_traffic_cmd = f"tcpdump -i {interface} -w {output_file}"
    base_filter = ""
    for filter_host in filter_hosts:
        if base_filter:
            base_filter += " and "
        base_filter += f"(not host {filter_host})"
    filter = None

    # Device traffic
    if device:
        device_mac, device_ip = device
        filter = f"host {device_ip} or ether host {device_mac}"
    
    # Other hosts' traffic (if needed)
    i = 1
    for other_host in other_hosts:
        other_ip = other_host[ConfigKeys.IPV4.value]
        try:
            other_ip = ip_address(other_ip)
        except ValueError:
            logger.error(f"Invalid IPv4 address: {other_ip}")
            continue

        other_interface = other_host[ConfigKeys.INTERFACE.value]
        other_filter = f"host {other_ip}"

        # Other host's traffic must be captured on the same interface as the device under test
        if other_interface == interface:
            if filter is None:
                filter = other_filter
            else:
                filter += f" or {other_filter}"

        # Start traffic capture for other host, on a different interface
        else:
            output_file_other = output_file.replace(".pcap", f"-{i}.pcap")
            final_filter = f"{base_filter} and {other_filter}"
            other_hosts_cmd = f"tcpdump -i {other_interface} -w {output_file_other} \"{final_filter}\""
            host.run(other_hosts_cmd, pty=True, asynchronous=True)
            i += 1

    # Start traffic capture on the device under test's interface
    final_filter = base_filter
    if filter is not None:
        if base_filter:
            final_filter += " and ("
        final_filter += filter
        if base_filter:
            final_filter += ")"
    device_traffic_cmd += f" \"{final_filter}\""
    host.run(device_traffic_cmd, pty=True, asynchronous=True)


def copy_to_remote(remote_host: str, local_file: str, remote_file: str) -> None:
    """
    Copy a file from localhost to a remote host.

    Args:
        remote_host (str): remote host's IP address
        local_file (str): path to the local file
        remote_file (str): path to the remote file
    Raises:
        Exception: if the file could not be copied
    """
    try:
        cmd = f"scp {local_file} {remote_host}:{remote_file}"
        subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        try:
            cmd = f"scp -O {local_file} {remote_host}:{remote_file}"
            subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise Exception(f"Could not copy {local_file} to {remote_host}:{remote_file}")


def copy_from_remote(remote_host: str, remote_file: str, local_file: str) -> None:
    """
    Copy a file from the router to the local machine.

    Args:
        remote_host (str): remote host's IP address
        remote_file (str): path to the remote file
        local_file (str): path to the local file
    Raises:
        Exception: if the file could not be copied
    """
    try:
        cmd = f"scp {remote_host}:{remote_file} {local_file}"
        subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        try:
            cmd = f"scp -O {remote_host}:{remote_file} {local_file}"
            subprocess.run(cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise Exception(f"Could not copy {remote_host}:{remote_file} to {local_file}")



##### MAIN RECURSION FUNCTION #####

def bfs_recursion(
        args: argparse.Namespace,
        config: dict,
        device: Any,
        router: Connection,
        tree: Tree,
        queue: deque
    ) -> None:
    """
    Recursive function, called for each node of the tree.

    Args:
        args (argparse.Namespace): command-line arguments
        config (dict): configuration
        device (Device): device under test
        router (fabric.Connection): SSH connection to the router
        tree (treelib.Tree): tree structure
        queue (collections.deque): queue of policies to process
    """

    global last_policy, is_app_on

    # Check if there are policies left to process
    if not queue:
        # Stop recursion
        logger.info("No more policies to process")
        return

    # There are policies left to process

    # Device metadata
    device_name = os.path.basename(args.device_dir)
    device_metadata = config[ConfigKeys.DEVICE.value]
    device_mac = device_metadata[ConfigKeys.MAC.value]
    device_ipv4 = device_metadata[ConfigKeys.IPV4.value]
    event = device_metadata[ConfigKeys.EVENT.value]
    device_event = f"{device_name}-{event}"
    event_dir = os.path.join(args.device_dir, event)
    ap_hostname = config[ConfigKeys.ACCESS_POINT.value][ConfigKeys.HOSTNAME.value]
    boot_plugs = config[ConfigKeys.BOOT_PLUGS.value] if event == "boot" else {}

    # Get next policy to process
    policy_name = queue.popleft()
    node = tree.get_node(policy_name)
    depth, policies = node.data
    policy_dir = os.path.join(event_dir, node.identifier)
    os.makedirs(policy_dir, exist_ok=True)

    # Visualize tree
    tree_utils.display_tree(tree, node.identifier)


    ### FIREWALL CONFIGURATION ###

    # Initial flush: reset to default configuration
    router.run("nft flush ruleset")
    router.run(f"killall {NFQUEUE_EXEC}", warn=True)
    
    if policies:

        # Derive firewall config
        device_name = os.path.basename(args.device_dir)
        device_data = {
            "name": device_name,
            "mac":  device_mac,
            "ipv4": device_ipv4
        }
        nfqueue_name = f"{device_name}_{node.identifier}"
        # Replace special characters in nfqueue name
        nfqueue_name = nfqueue_name.replace(':', '_').replace('#', '_').replace('.', '_').replace('/', '_').replace('*', '_').replace('?', '_').replace('=', '_')
        translate_policies(device_data, policies, nfqueue_name=nfqueue_name, output_dir=policy_dir)
        nft_script_path = os.path.join(policy_dir, NFTABLES_SCRIPT)
        
        try:
            copy_to_remote(ap_hostname, nft_script_path, ROUTER_NFTABLES_SCRIPT)
        except Exception as e:
            logger.error(e)
            logger.error("Continue recursion at next policy...")
            bfs_recursion(args, config, device, router, tree, queue)
            return
        
        nfqueue_src_path = os.path.join(policy_dir, NFQUEUE_SRC)

        # If policy requires an NFQueue,
        # cross-compile the NFQueue program and start it
        if os.path.isfile(nfqueue_src_path):

            # Cross-compile using Docker container
            docker_env_file = os.path.join(BASE_DIR, "docker.env")
            with open(docker_env_file, "w") as f:
                f.write(f"DEVICE={device_name}\n")
                f.write(f"EVENT={event}\n")
                f.write(f"NFQUEUE={node.identifier}\n")
            cmd = f"docker compose run --rm --remove-orphans cross-compilation /home/user/iot-firewall/docker_cmd.sh tl-wdr4900 {os.getuid()} {os.getgid()}"
            proc = subprocess.run(cmd.split(), capture_output=True)
            logger.info(str(proc.stdout.decode()))
            if proc.stderr:
                logger.error(str(proc.stderr.decode()))

            # Verify cross-compiled executable was correctly generated
            nfqueue_exec_path = os.path.join(BASE_DIR, "bin", nfqueue_name)
            if not os.path.isfile(nfqueue_exec_path):
                logger.error(f"Cross-compiled nfqueue executable not found at {nfqueue_exec_path}")
                logger.error("Continue recursion at next policy...")
                bfs_recursion(args, config, device, router, tree, queue)
                return

            try:
                copy_to_remote(ap_hostname, nfqueue_exec_path, ROUTER_NFQUEUE_EXEC)
            except Exception as e:
                logger.error(e)
                logger.error("Continue recursion at next policy...")
                bfs_recursion(args, config, device, router, tree, queue)
                return

            router.run(f"{ROUTER_NFQUEUE_EXEC} &")

        router.run(f"nft -f {ROUTER_NFTABLES_SCRIPT}")


    ### USER EVENT LOOP ###

    ## Files
    # Timestamps
    event_timestamps_file = os.path.join(policy_dir, "timestamps.txt")
    open(event_timestamps_file, "w").close()  # Truncate timestamps file to 0 bytes
    # PCAPs
    traces_dir = os.path.join(policy_dir, "traces")
    os.makedirs(traces_dir, exist_ok=True)

    ### Start app
    if not is_app_on and event != "boot":
        for _ in range(5):
            try:
                device.start_app()
            except IndexError:
                is_app_on = False
                logger.error("Could not connect to ADB device.")
                logger.error("Retrying in 10 seconds...")
                time.sleep(10)
            else:
                is_app_on = True
                logger.info("Started app.")
                break
        
        if is_app_on:
            time.sleep(10)
        else:
            logger.error("Could not start app.")
            logger.error("Stopping recursion...")
            return


    ### Event iteration
    n_events = config[ConfigKeys.EXP_PARAM.value][ConfigKeys.N_EVENTS.value]
    n_successful_events = 0
    gateway_hostname = config[ConfigKeys.GATEWAY.value][ConfigKeys.HOSTNAME.value]
    dns_table = read_dns_cache(gateway_hostname)
    for _ in range(0, n_events):

        # Random wait time before next event
        wait_low = config[ConfigKeys.EXP_PARAM.value][ConfigKeys.WAIT_LOW.value]
        wait_high = config[ConfigKeys.EXP_PARAM.value][ConfigKeys.WAIT_HIGH.value]
        wait_time = random.randint(wait_low, wait_high)

        # Get device state before event execution
        if event != "boot":
            try:
                state_before = device.get_state()
            except Exception:
                logger.error("Could not get device state before event execution.")
                logger.info(f"Waiting {wait_time} seconds before next event...")
                time.sleep(wait_time)
                continue
        
        # Append timestamp
        timestamp = int(time.time())
        with open(event_timestamps_file, "a") as f:
            f.write(f"{timestamp}\n")


        ## Start packet capture

        pcap_basename = f"{timestamp}.pcap"
        router_pcap_path = os.path.join("/", "tmp", pcap_basename)
        logger.info(f"Starting packet capture for event {device_event}...")
        interface = device_metadata[ConfigKeys.ACCESS_POINT_INTERFACE.value]

        try:
            other_hosts = config[ConfigKeys.OTHER_HOSTS.value]
        except KeyError:
            other_hosts = []

        try:
            filter_hosts = config[ConfigKeys.FILTER_HOSTS.value]
        except KeyError:
            filter_hosts = []
        
        pcap_timeout = config[ConfigKeys.EXP_PARAM.value][ConfigKeys.PCAP_TIMEOUT.value]
        start_traffic_capture(router,
                              interface,
                              router_pcap_path,
                              (device_mac, device_ipv4),
                              other_hosts,
                              filter_hosts)

        # Trigger user event
        try:
            if event == "boot":
                for plug in boot_plugs.values():
                    plug.boot()
            else:
                getattr(device, event)()  # Add necessary additional arguments here
        except IndexError:
            logger.error("Could not connect to ADB device.")
            is_event_successful = False
            # Stop packet capture        
            router.run("killall tcpdump")
            logger.info(f"Stopped packet capture for event {device_event}")
        else:
            logger.info(f"Executed event \"{device_event}\"")
            time.sleep(pcap_timeout)
            # Stop packet capture        
            router.run("killall tcpdump")
            logger.info(f"Stopped packet capture for event {device_event}")
            # Update DNS table
            dns_table = update_dns_table(dns_table, host=gateway_hostname)
            # Check if event was successful
            is_event_successful = device.is_event_successful(state_before) if event != "boot" else True

            # If event is "boot", shutdown device before next iteration
            if event == "boot":
                for plug in boot_plugs.values():
                    plug.shutdown()
        

        if is_event_successful:
            logger.info(f"Event {device_event} was successful.")
            n_successful_events += 1

            ## Move captured PCAP files to host
            has_exception = False
            local_pcap_path_device = os.path.join(traces_dir, pcap_basename)
            if other_hosts:
                local_pcap_path_device = local_pcap_path_device.replace(".pcap", "-device.pcap")
            logger.info(f"Local PCAP path: {local_pcap_path_device}")

            # Device traffic
            try:
                copy_from_remote(ap_hostname, router_pcap_path, local_pcap_path_device)
            except Exception as e:
                has_exception = True
                logger.error(e)

            # Other hosts' traffic
            if not has_exception and other_hosts:
                router_pcap_path_others = router_pcap_path.replace(".pcap", "-*.pcap")
                logger.info(f"Router PCAP path for other hosts: {router_pcap_path_others}")
                try:
                    copy_from_remote(ap_hostname, router_pcap_path_others, traces_dir)
                except Exception as e:
                    has_exception = True
                    logger.error(e)

                if not has_exception:
                    # Merge device and other hosts' PCAPs
                    local_pcap_path = local_pcap_path_device.replace("-device.pcap", ".pcap")
                    pcaps_to_merge = glob.glob(local_pcap_path_device.replace("-device.pcap", "*.pcap"))
                    logger.info(f"PCAPs to merge: {pcaps_to_merge}")
                    logger.info(f"Output PCAP: {local_pcap_path}")
                    cmd = f"mergecap -w {local_pcap_path} {" ".join(pcaps_to_merge)}"
                    try:
                        subprocess.run(cmd.split(), check=True)
                    except subprocess.CalledProcessError as e:
                        logger.error(e)
                    finally:
                        for pcap in pcaps_to_merge:
                            os.remove(pcap)
        
        else:
            logger.error("Event failed.")
        
        
        # Remove PCAP file(s) from router
        router.run(f"rm /tmp/{timestamp}*.pcap", warn=True)

        # Wait before next event iteration
        wait_time -= pcap_timeout
        logger.info(f"Waiting {wait_time} seconds before next event...")
        time.sleep(wait_time)


    ### Close app
    if event != "boot":
        for _ in range(5):
            try:
                device.close_app()
            except IndexError:
                is_app_on = True
                logger.error("Could not connect to ADB device.")
                logger.error("Retrying in 10 seconds...")
                time.sleep(10)
            else:
                is_app_on = False
                break


    # Flush firewall
    router.run("nft flush ruleset")
    router.run(f"killall {NFQUEUE_EXEC}", warn=True)

    # Remove leftover PCAP files from router
    router.run("rm /tmp/*.pcap", warn=True)

    # Save DNS table
    dns_table_path = os.path.join(policy_dir, "dns_table.json")
    with open(dns_table_path, "w") as f:
        json.dump(dns_table, f, indent=2)
    

    ### SIGNATURE EXTRACTION ###

    # If event iteration failed too many times,
    # skip signature extraction,
    # and continue recursion at next policy
    if n_successful_events < n_events / 2:
        logger.error(f"Event iteration for policy {policy_name} failed too many times. Continue recursion at next policy...")
        bfs_recursion(args, config, device, router, tree, queue)
        return

    # Event iteration was successful

    pcaps = glob.glob(f"{traces_dir}/*.pcap")
    signature = pcaps_to_signature_pattern(pcaps, dns_table, pcap_timeout)
    signature_csv_path = os.path.join(policy_dir, "signature.csv")
    signature.to_csv(signature_csv_path)
    flows = signature.get_flows()
    for flow in flows:

        # Generate next policy and add it to the tree
        next_policy_name = f"{depth + 1}_{flow.get_unique_id()}"
        next_policy = flow.extract_policy(device_ipv4)
        next_policies = deepcopy(policies)
        next_policies.append(next_policy)

        # If policy has not been processed yet,
        # add it to the queue
        if not tree_contains_policy(next_policy, tree):
            last_policy = (next_policy_name, next_policy)
            queue.append(next_policy_name)

        # Add child policy to the tree
        tree.create_node(next_policy_name, next_policy_name, data=(depth + 1, next_policies), parent=node.identifier)
    

    # Continue recursion
    bfs_recursion(args, config, device, router, tree, queue)



##### MAIN FUNCTION #####

def main() -> None:

    global last_policy
    
    ### ARGUMENT PARSING ###

    parser = argparse.ArgumentParser(description="Run experiments for dynamic fingerprinting of IoT devices")
    ## Experimental setup
    # Optional argument -c: config file
    parser.add_argument("-c", "--config", type=str, default="config.yaml", help="Path to configuration file. Default is `config.yaml`.")
    # Optional argument -d: device directory
    parser.add_argument("-d", "--device-dir", type=str, help="Directory of the device under test. By default, creates a new directory in the current working directory.")
    # Optional argument -l: log file
    parser.add_argument("-l", "--log", type=str, help="Path to a log file to write")
    ## Data structures
    # Optional argument --tree: tree file
    parser.add_argument("--tree", type=str, default=None, help="Path to a tree file to load")
    # Optional argument --queue: queue file
    parser.add_argument("--queue", type=str, default=None, help="Path to a queue file to load")
    # Parse arguments
    args = parser.parse_args()

    # Read config file
    config = {}
    with open(args.config, "r") as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError:
            logger.error("Could not read config file.")
            exit(-1)

    ## Validate device metadata
    try:
        device_metadata = config[ConfigKeys.DEVICE.value]
    except KeyError:
        logger.error("Device metadata not found in config file.")
        exit(-1)
    
    try:
        device_mac = device_metadata[ConfigKeys.MAC.value]
        device_mac = mac_address(device_mac)
    except KeyError:
        logger.error("Device MAC address not found in config file.")
        exit(-1)
    except ValueError:
        logger.error(f"Invalid device MAC address: {device_mac}")
        exit(-1)

    try:
        device_ipv4 = device_metadata[ConfigKeys.IPV4.value]
        device_ipv4 = ip_address(device_ipv4)
    except KeyError:
        logger.error("Device IPv4 address not found in config file.")
        exit(-1)
    except ValueError:
        logger.error(f"Invalid device IPv4 address: {device_ipv4}")
        exit(-1)
        

    device_name = device_metadata[ConfigKeys.NAME.value]
    event = device_metadata[ConfigKeys.EVENT.value]
    event_dir = os.path.join(args.device_dir, event)

    if event == "boot":
        try:
            config_boot_plugs = config[ConfigKeys.BOOT_PLUGS.value]
        except KeyError:    
            logger.error("Boot plugs not found in config file.")
            exit(-1)
        else:
            config[ConfigKeys.BOOT_PLUGS.value] = {}
            boot_plugs = config[ConfigKeys.BOOT_PLUGS.value]
            for name, data in config_boot_plugs.items():
                plug_class = getattr(importlib.import_module("utils.power_cycle"), name)
                boot_plugs[name] = plug_class(**data)
    
    # If device directory is not provided, create a new one
    if args.device_dir is None:
        args.device_dir = os.path.join(os.getcwd(), device_name)
    os.makedirs(args.device_dir, exist_ok=True)
 

    # Logger config
    log_file = os.path.join(event_dir, "experiments.log") if args.log is None else args.log
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(filename=log_file, filemode="w", level=logging.INFO)
    logger.info(f"Started experiments at {time.ctime()}")


    ## Network setup
    # Test connectivity
    ap_ip = ip_address(config[ConfigKeys.ACCESS_POINT.value][ConfigKeys.IPV4.value])
    interface_to_ap = config[ConfigKeys.ACCESS_POINT.value][ConfigKeys.CONNECTED_TO.value]
    # if not is_connected(ap_ip, interface_to_ap):
    #     raise Exception(f"Could not reach {ap_ip} on {interface_to_ap}")
    # Setup SSH connections
    ssh_config = Config(overrides={"run": {"hide": True}})
    ap_hostname = config[ConfigKeys.ACCESS_POINT.value][ConfigKeys.HOSTNAME.value]
    router = Connection(ap_hostname, config=ssh_config)  # LAN AP
    # Start adb
    if event != "boot":
        cmd = "adb devices"
        proc = subprocess.run(cmd.split(), capture_output=True)
        logger.info(str(proc.stdout.decode()))
        if proc.stderr:
            logger.error(str(proc.stderr.decode()))


    ## Data structures

    # Tree
    tree = None
    last_policy = None
    if args.tree is not None:
        try:
            tree_json = {}
            with open(args.tree, "r") as f:
                tree_json = json.load(f)
        except json.JSONDecodeError:
            # Initialize empty tree
            tree = tree_utils.init_empty_tree()
        else:
            # Build tree from JSON data
            tree = tree_utils.build_tree(Tree(), tree_json)
            try:
                # Get last policy, if any
                last_policy = tree_utils.find_last_policy(tree_json)
            except KeyError:
                # No last policy found
                last_policy = None
    else:
        # Initialize empty tree
        tree = tree_utils.init_empty_tree()

    # Queue
    queue = None
    if args.queue is not None:
        try:
            # Read existing queue
            with open(args.queue, "r") as f:
                queue = deque(f.read().split(","))
                # Add last policy read from tree, if any
                if last_policy is not None:
                    queue.appendleft(last_policy)
        except FileNotFoundError:
            # Existing queue not found,
            # initialize empty queue
            queue = deque(["0_root"])
    else:
        # No existing queue,
        # initialize empty queue
        queue = deque(["0_root"])


    ## Start recursion
    device_metadata = config[ConfigKeys.DEVICE.value]
    device_name = os.path.basename(args.device_dir)
    device = init_device(
        device_name,
        device_metadata[ConfigKeys.IPV4.value],
        # Add necessary additional arguments here
        )
    
    # Set in initial state
    if event == "boot":
        # Shutdown devices before starting recursion
        for plug in boot_plugs.values():
            plug.shutdown()
    else:
        device.close_app()  # Reset app before starting recursion

    try:
        bfs_recursion(args, config, device, router, tree, queue)
    finally:
        # Clean up
        if event != "boot":
            device.close_app()
        router.run("nft flush ruleset")
        router.run(f"killall {NFQUEUE_EXEC}", warn=True)

        # Display final tree
        tree_utils.display_tree(tree)
        
        ### Save recursion data
        ## Tree
        # TXT
        tree_txt_path = os.path.join(event_dir, "tree.txt")
        tree_utils.save_to_txt(tree, tree_txt_path)
        # JSON
        last_policy_name = last_policy[0] if last_policy else None
        tree_json_path = os.path.join(event_dir, "tree.json")
        tree_utils.save_to_json(tree, tree_json_path, last_policy_name)
        ## Queue
        queue_path = os.path.join(event_dir, "queue.txt")
        with open(queue_path, "w") as f:
            f.write(",".join(queue))


if __name__ == "__main__":
    main()
