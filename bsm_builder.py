# test.py

import concurrent.futures
import logging
import os
import re
import time

from typing import List

from dotenv import load_dotenv
from tqdm import tqdm

from pyonms import PyONMS
from pyonms.dao.nodes import NodeComponents
from pyonms.models.business_service import (
    BusinessService,
    BusinessServiceRequest,
    IPServiceEdgeRequest,
    MapFunction,
    Attribute,
    Severity,
)

load_dotenv()

LOG_PATH = os.environ.get("log_path", "./logs/bsm_topo_DATE.log").replace(
    "DATE", time.strftime("%Y-%m-%d")
)

log_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] (Thread-%(thread)s) %(message)s"
)
logger = logging.getLogger("bsm_builder")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOG_PATH)
fh.setFormatter(log_formatter)
fh.setLevel(logging.DEBUG)

logger.addHandler(fh)

# The first service that matches will be used as the edge for the node.
# Values here will be a substring match to the node's monitored service name.
CRITICAL_SERVICES = ["ICMP", "VC-EDGE", "SP-Edge"]

# Node asset record manufacturer values to include if the node label doesn't match the regex pattern.
# Values here will be an exact match to the node asset record.
MANUFACTURERS = ["Velocloud", "SilverPeak"]


def generate_bsm_list(server: PyONMS, all_bsms: list, threads: int = 25) -> dict:
    logger.info("Gathering nodes from inventory")
    nodes = server.nodes.get_nodes(
        limit=0, batch_size=100, components=[NodeComponents.IP], threads=threads
    )
    logger.info(f"Found {len(nodes)} nodes")
    logger.info("Parsing nodes into site groupings")
    bsm_list = {}
    for node in tqdm(nodes, desc="Grouping nodes into sites", unit="node"):
        if not node.assetRecord.displayCategory:
            continue
        match = re.match(
            "MI_(?P<org>.*)-(?P<host>.*)(?P<instance>[0-9][0-9])(?P<function>S|VMR|DNFVI|DNFV|-vFW)",
            node.label,
        )
        # match1 for VC-EDGE devices
        # match1 = re.match(
        #     "MI_(?P<org>.*)-(?P<instance>.*)",
        #     node.label,
        # )
        if match:
            payload = {
                "node": node,
                "instance": match.group("instance"),
                "function": match.group("function"),
                "friendly_name": f'{match.group("instance")}{match.group("function")}',
            }
            if bsm_list.get(node.assetRecord.displayCategory):
                bsm_list[node.assetRecord.displayCategory]["nodes"].append(payload)
            else:
                bsm_list[node.assetRecord.displayCategory] = {
                    "nodes": [payload],
                    "instance": match.group("instance"),
                }
        elif node.assetRecord.manufacturer in MANUFACTURERS:
            payload = {
                "node": node,
                "instance": None,
                "function": "EDGE",
                "friendly_name": "EDGE",
            }
            if bsm_list.get(node.assetRecord.displayCategory):
                bsm_list[node.assetRecord.displayCategory]["nodes"].append(payload)
            else:
                bsm_list[node.assetRecord.displayCategory] = {
                    "nodes": [payload],
                    "instance": None,
                }
        # elif match1:
        #     payload = {
        #         "node": node,
        #         "instance": match1.group("instance"),
        #         "function": "",
        #         "friendly_name": "EDGE",
        #     }
        #     if bsm_list.get(node.assetRecord.displayCategory):
        #         bsm_list[node.assetRecord.displayCategory]["nodes"].append(payload)
        #     else:
        #         bsm_list[node.assetRecord.displayCategory] = {
        #             "nodes": [payload],
        #             "instance": match1.group("instance"),
        #         }

    for group, data in bsm_list.items():
        for bsm in all_bsms:
            if group == bsm.name:
                data["bsm"] = bsm
                break
    logger.info(f"Found {len(bsm_list)} sites")
    logger.info("Completed group generation")
    return bsm_list


def cleanup_bsms(server: PyONMS, all_bsms: List[BusinessService]) -> None:
    logger.info("Starting cleanup of empty Business Services")
    empty_bsms = []
    for bsm in tqdm(all_bsms, desc="Checking for empty BSMs", unit="bsm"):
        if (
            not bsm.application_edges
            and not bsm.child_edges
            and not bsm.ip_services_edges
            and not bsm.reduction_key_edges
        ):
            empty_bsms.append(bsm)
    for bsm in tqdm(empty_bsms, desc="Deleting empty BSMs", unit="bsm"):
        server.bsm.delete_bsm(bsm.id)
        logging.info(f"Removed {bsm.name}: No nodes for site in inventory.")
    logger.info("Completed cleanup of empty Business Services")


def generate_ip_edge(
    node: dict, service_id: int, friendly_name: str
) -> IPServiceEdgeRequest:
    if node["function"] in ["S"]:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.CRITICAL),
        )

    elif node["function"] in ["DNFVI", "DNFV"]:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(
                type="SetTo",
                status=Severity.MAJOR,
            ),
        )

    elif node["function"] in ["VMR"]:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(
                type="SetTo",
                status=Severity.MINOR,
            ),
        )

    elif node["function"] in ["EDGE"]:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.WARNING),
        )

    else:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.WARNING),
        )


def check_include_service(service: str):
    for include_service in CRITICAL_SERVICES:
        if include_service in service:
            return True
    return False


def process_site(server: PyONMS, group: str, data: dict) -> str:
    old_bsm = server.bsm.find_bsm_name(name=group, cache_only=True)
    if old_bsm:
        new_bsm = old_bsm.request()
    else:
        new_bsm = BusinessServiceRequest(name=group)
    new_bsm.add_attribute(Attribute(key="model", value="device"))
    for node in data["nodes"]:
        for ip in node["node"].ipInterfaces:
            if ip.snmpPrimary.value == "P":
                for service in ip.services:
                    if check_include_service(service=service.serviceType.name):
                        friendly_name = node["friendly_name"]
                        edge = generate_ip_edge(
                            node=node,
                            service_id=service.id,
                            friendly_name=friendly_name,
                        )
                        new_bsm.update_edge(ip_edge=edge)
                        break
    if old_bsm:
        if old_bsm.request().to_dict() == new_bsm.to_dict():
            logger.info(
                f"No changes to site {group} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
            )
        else:
            server.bsm.update_bsm(bsm=new_bsm, id=old_bsm.id)
            logger.info(
                f"Updated site {group} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
            )
    else:
        server.bsm.create_bsm(new_bsm)
        logger.info(
            f"Created site {group} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
        )
    return group


def process_instance(server: PyONMS, threads: int = 10) -> None:
    logger.info("Reloading BSM Daemon")
    server.bsm.reload_bsm_daemon()
    logger.info("Refreshing BSM Cache")
    all_bsms = server.bsm.get_bsms(threads=threads)
    bsm_list = generate_bsm_list(server=server, all_bsms=all_bsms, threads=threads)
    if threads > len(bsm_list.keys()):
        threads = len(bsm_list.keys())
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        with tqdm(
            total=len(bsm_list.keys()), unit="site", desc="Updating BSM models"
        ) as progress:
            futures = []
            for group, data in bsm_list.items():
                future = pool.submit(
                    process_site, server=server, group=group, data=data
                )
                future.add_done_callback(lambda p: progress.update())
                futures.append(future)
            results = []
            for future in futures:
                try:
                    result = future.result()
                except Exception as e:
                    print(f"{e}")
                    time.sleep(5)
                    future = pool.submit(
                        process_site, server=server, group=group, data=data
                    )
                    result = future.result()
                results.append(result)
    logger.info("Reloading BSM Daemon")
    server.bsm.reload_bsm_daemon()
    logger.info("Refreshing BSM Cache")
    all_bsms = server.bsm.get_bsms(threads=threads)
    cleanup_bsms(server=server, all_bsms=all_bsms)


def main():
    hostname = os.getenv("bsm_hostname")
    username = os.getenv("bsm_username")
    password = os.getenv("bsm_password")
    if not hostname and not username and not password:
        from instances import instances

        for instance in instances.values():
            hostname = instance["hostname"]
            username = instance["username"]
            password = instance["password"]
            break
        with open(".env", "w") as f:
            f.write(f"bsm_hostname={hostname}\n")
            f.write(f"bsm_username={username}\n")
            f.write(f"bsm_password={password}\n")
    server = PyONMS(hostname=hostname, username=username, password=password)
    process_instance(server, threads=25)


if __name__ == "__main__":
    logger.info("Starting BSM sync")
    main()
    logger.info("Completed BSM sync")
