# bsm_builder.py

import concurrent.futures
import logging
import os
import re
import time
from typing import List

from pyonms import PyONMS
from pyonms.dao.nodes import NodeComponents
from pyonms.models.business_service import (
    Attribute,
    BusinessService,
    BusinessServiceRequest,
    ChildEdgeRequest,
    IPServiceEdgeRequest,
    MapFunction,
    Severity,
)
from tqdm import tqdm

# import models

# The first service that matches will be used as the edge for the node.
# Values here will be a substring match to the node's monitored service name.
CRITICAL_SERVICES = ["ICMP", "VC-EDGE", "SP-Edge"]

# Node asset record manufacturer values to include if the node label doesn't match the regex pattern.
# Values here will be an exact match to the node asset record.
MANUFACTURERS = ["velocloud", "silverpeak"]

CRITICAL_FUNCTIONS = ["SAOS", "S", "SAOS1"]
MAJOR_FUNCTIONS = ["DNFVI", "DNFV", "DNFVI1"]
MINOR_FUNCTIONS = ["VMR", "VMR1", "RTR01"]
# WARNING_FUNCTIONS = ["EDGE", "SP-1", "SP-2"]

FUNCTIONS = MINOR_FUNCTIONS + MAJOR_FUNCTIONS + CRITICAL_FUNCTIONS

MODEL_NUMBER = ["edge kvm", "virtual"]
SECONDARY_DEVICES = ["02", "03", "04", "05", "06", "07", "08", "09"]


def setup_logging(instance_name: str, process: str = "main") -> logging.Logger:
    logger = logging.getLogger(f"{instance_name}-{process}")
    logger.setLevel(logging.DEBUG)

    # bsm_log_path = os.environ['bsm_log_path']

    # LOG_PATH = os.environ.get(
    #    "log_path", bsm_log_path + f"/logs/bsm_{instance_name}_DATE.log"
    # ).replace("DATE", time.strftime("%Y-%m-%d"))

    LOG_PATH = (
        os.environ.get("log_path", "./logs/bsm_INSTANCE_DATE.log")
        .replace("DATE", time.strftime("%Y-%m-%d"))
        .replace("INSTANCE", instance_name)
    )
    log_formatter = logging.Formatter(
        f"%(asctime)s %(levelname)s [{instance_name}] (Thread-%(thread)s-%(funcName)s) %(message)s"
    )
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(log_formatter)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    return logger


def generate_bsm_list(  # noqa C901
    server: PyONMS, all_bsms: list, logger: logging.Logger, threads: int = 25
) -> dict:
    logger.info("Gathering nodes from inventory")
    nodes = server.nodes.get_nodes(
        limit=0,
        batch_size=100,
        components=[NodeComponents.IP, NodeComponents.SERVICES],
        threads=threads,
    )
    logger.info(f"Found {len(nodes)} nodes")
    logger.info("Parsing nodes into site groupings")
    bsm_list = {}
    regex_search = re.compile(
        f"^MI_(?P<org>.*)-(?P<host>.*)(?P<instance>\d\w+?)-?(?P<function>{'|'.join(FUNCTIONS)})$"  # noqa W605
    )
    for node in tqdm(
        nodes,
        desc=f"Grouping {server.name} nodes into sites",
        unit="node",
    ):
        if not node.assetRecord.displayCategory:
            continue
        match = regex_search.match(node.label)
        if match:
            instance = match.group("instance")
            payload = {
                "node": node,
                "instance": instance,
                "function": match.group("function"),
                "friendly_name": f'{instance}{match.group("function")}',
            }
            if bsm_list.get(node.assetRecord.displayCategory):
                if bsm_list[node.assetRecord.displayCategory].get(instance):
                    bsm_list[node.assetRecord.displayCategory][instance][
                        "nodes"
                    ].append(payload)
                else:
                    bsm_list[node.assetRecord.displayCategory][instance] = {
                        "nodes": [payload],
                        "instance": instance,
                        "service_name": f"{node.assetRecord.displayCategory}_{instance}",
                    }
            else:
                bsm_list[node.assetRecord.displayCategory] = {
                    instance: {
                        "nodes": [payload],
                        "instance": instance,
                        "service_name": f"{node.assetRecord.displayCategory}_{instance}",
                    }
                }
        elif ((node.assetRecord.manufacturer or "").lower() in MANUFACTURERS) and (
            (node.assetRecord.modelNumber or "").lower() in MODEL_NUMBER
        ):
            instance = "00"
            payload = {
                "node": node,
                "instance": instance,
                "function": "EDGE",
                "friendly_name": "EDGE",
            }
            if bsm_list.get(node.assetRecord.displayCategory):
                if bsm_list[node.assetRecord.displayCategory].get(instance):
                    bsm_list[node.assetRecord.displayCategory][instance][
                        "nodes"
                    ].append(payload)
                else:
                    bsm_list[node.assetRecord.displayCategory][instance] = {
                        "nodes": [payload],
                        "instance": instance,
                        "service_name": f"{node.assetRecord.displayCategory}_{instance}",
                    }
            else:
                bsm_list[node.assetRecord.displayCategory] = {
                    instance: {
                        "nodes": [payload],
                        "instance": instance,
                        "service_name": f"{node.assetRecord.displayCategory}_{instance}",
                    }
                }

    for name, instance_data in bsm_list.items():
        instance_data["bsm"] = server.bsm.find_bsm_name(name=name, cache_only=True)
        for instance_id, site_data in instance_data.items():
            if instance_id in ["bsm"]:
                continue
            site_data["bsm"] = server.bsm.find_bsm_name(
                name=site_data["service_name"], cache_only=True
            )
    logger.info(f"Found {len(bsm_list)} sites")
    logger.info("Completed group generation")
    return bsm_list


def cleanup_bsms(
    server: PyONMS, all_bsms: List[BusinessService], logger: logging.Logger
) -> None:
    logger.info("Starting cleanup of empty Business Services")
    empty_bsms = []
    for bsm in tqdm(
        all_bsms,
        desc=f"Checking {server.name} for empty BSMs",
        unit="bsm",
    ):
        if (
            not bsm.application_edges
            and not bsm.child_edges
            and not bsm.ip_services_edges
            and not bsm.reduction_key_edges
        ):
            empty_bsms.append(bsm)
    for bsm in tqdm(
        empty_bsms,
        desc=f"Deleting {server.name} empty BSMs",
        unit="bsm",
    ):
        server.bsm.delete_bsm(bsm=bsm)
        logger.info(f"Removed {bsm.name}: No nodes for site in inventory.")
    logger.info("Completed cleanup of empty Business Services")


def generate_ip_edge(
    node: dict, service_id: int, friendly_name: str, logger: logging.Logger
) -> IPServiceEdgeRequest:
    if node["function"] in CRITICAL_FUNCTIONS:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.CRITICAL),
        )

    elif node["function"] in MAJOR_FUNCTIONS:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.MAJOR),
        )

    elif node["function"] in MINOR_FUNCTIONS:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.MINOR),
        )

    # elif node["function"] in WARNING_FUNCTIONS:
    #    return IPServiceEdgeRequest(
    #        friendly_name=friendly_name,
    #        ip_service_id=service_id,
    #        map_function=MapFunction(type="SetTo", status=Severity.WARNING),
    #    )

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


def process_site(server: PyONMS, group_name: str, site: dict) -> str:  # noqa C901
    logger = setup_logging(instance_name=server.name, process=group_name)
    for instance, data in site.items():
        if instance in ["bsm"]:
            continue
        if data.get("bsm"):
            old_bsm = data["bsm"]
            new_bsm = data["bsm"].request()
        else:
            old_bsm = server.bsm.find_bsm_name(
                name=data["service_name"], cache_only=True
            )
            if old_bsm:
                new_bsm = old_bsm.request()
            else:
                new_bsm = BusinessServiceRequest(name=data["service_name"])
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
                                logger=logger,
                            )
                            new_bsm.update_edge(ip_edge=edge)
                            break
        if len(new_bsm.ip_service_edges) <= 1:
            pass  # 856 singles # continue
        if old_bsm:
            if old_bsm.request().to_dict() == new_bsm.to_dict():
                logger.info(
                    f"No changes to site {data['service_name']} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
                )
            else:
                server.bsm.update_bsm(bsm=new_bsm, id=old_bsm.id)
                logger.info(
                    f"Updated site {data['service_name']} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
                )
        else:
            server.bsm.create_bsm(new_bsm)
            logger.info(
                f"Created site {data['service_name']} with nodes: {', '.join([node['node'].label for node in data['nodes']])}"
            )
    return group_name


def group_site_services(server: PyONMS, group_name: str, site: dict):  # noqa C901
    if len([id for id in site.keys() if id != "bsm"]) < 2:
        return group_name
    logger = setup_logging(instance_name=server.name, process=group_name)
    if isinstance(site.get("bsm"), BusinessService):
        old_bsm = site["bsm"]
        new_bsm = site["bsm"].request()
    else:
        old_bsm = None
        new_bsm = BusinessServiceRequest(name=group_name)
    new_bsm.add_attribute(Attribute(key="model", value="site"))
    for instance, data in site.items():
        if instance in ["bsm"]:
            continue
        if data.get("bsm"):
            new_bsm.update_edge(child_edge=ChildEdgeRequest(child_id=data["bsm"].id))

    if len(new_bsm.child_edges) <= 1:
        return group_name
    if old_bsm:
        if old_bsm.request().to_dict() == new_bsm.to_dict():
            logger.info(f"No changes to site {group_name}")
        else:
            server.bsm.update_bsm(bsm=new_bsm, id=old_bsm.id)
            logger.info(f"Updated site {group_name}")
    else:
        server.bsm.create_bsm(new_bsm)
        logger.info(f"Created site {group_name}")
    return group_name


def process_instance(server: PyONMS, logger: logging.Logger, threads: int = 10) -> None:
    logger.info("Reloading BSM Daemon")
    server.bsm.reload_bsm_daemon()
    logger.info("Refreshing BSM Cache")
    all_bsms = server.bsm.get_bsms(threads=threads)
    bsm_list = generate_bsm_list(
        server=server, all_bsms=all_bsms, threads=threads, logger=logger
    )
    if threads > len(bsm_list.keys()):
        threads = len(bsm_list.keys())
    if threads == 0:
        threads = 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        with tqdm(
            total=len(bsm_list.keys()),
            unit="site",
            desc=f"Updating {server.name} BSM instance models",
        ) as progress:
            futures = []
            for group, data in bsm_list.items():
                # process_site(server=server, group_name=group, site=data)
                future = pool.submit(
                    process_site, server=server, group_name=group, site=data
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
                        process_site,
                        server=server,
                        group_name=group,
                        data=data,
                    )
                    result = future.result()
                results.append(result)
    logger.info("Reloading BSM Daemon")
    server.bsm.reload_bsm_daemon()
    all_bsms = server.bsm.get_bsms(threads=threads)
    bsm_list = generate_bsm_list(
        server=server, all_bsms=all_bsms, threads=threads, logger=logger
    )
    logger.info("Refreshing BSM Cache")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        with tqdm(
            total=len(bsm_list.keys()),
            unit="site",
            desc=f"Updating {server.name} BSM site models",
        ) as progress:
            futures = []
            for group, data in bsm_list.items():
                # process_site(server=server, group_name=group, site=data)
                future = pool.submit(
                    group_site_services, server=server, group_name=group, site=data
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
                        group_site_services,
                        server=server,
                        group_name=group,
                        data=data,
                    )
                    result = future.result()
                results.append(result)
    logger.info("Reloading BSM Daemon")
    server.bsm.reload_bsm_daemon()
    logger.info("Refreshing BSM Cache")
    all_bsms = server.bsm.get_bsms(threads=threads)
    cleanup_bsms(server=server, all_bsms=all_bsms, logger=logger)


def instance_builder(server: PyONMS, fresh: bool = False, threads: int = 10):
    logger = setup_logging(instance_name=server.name)
    logger.info("Starting BSM sync")
    if fresh:
        delete_all_bsms(server=server, logger=logger, threads=threads)
    process_instance(server, threads=threads, logger=logger)
    logger.info("Completed BSM sync")


def delete_all_bsms(server: PyONMS, logger: logging.Logger, threads: int = 10):
    logger.info("Starting cleanup of all Business Services")
    all_bsms = server.bsm.get_bsms(threads=threads)
    for bsm in tqdm(
        all_bsms,
        desc=f"Deleting all {server.name} BSMs",
        unit="bsm",
    ):
        server.bsm.delete_bsm(bsm=bsm)
    server.bsm.reload_bsm_daemon()
    logger.info("Completed cleanup of all Business Services")


def main(threads: int = 10, fresh: bool = False):
    from instances import instances

    for instance_name, instance in instances.items():
        hostname = instance["hostname"]
        username = instance["username"]
        password = instance["password"]
        server = PyONMS(
            hostname=hostname, username=username, password=password, name=instance_name
        )
        instance_builder(server=server, fresh=fresh, threads=threads)


if __name__ == "__main__":
    # main(threads=25, fresh=False)
    pass
