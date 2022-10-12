# test.py

import concurrent.futures
import os
import re
import time

from dotenv import load_dotenv

from typing import List
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


def get_bsm_list(server: PyONMS, all_bsms: list, threads: int = 25) -> dict:
    nodes = server.nodes.get_nodes(
        limit=0, batch_size=100, components=[NodeComponents.IP], threads=threads
    )

    bsm_list = {}
    for node in nodes:
        if not node.assetRecord.displayCategory:
            continue
        match = re.match(
            "MI_(?P<org>.*)-(?P<host>.*)(?P<instance>[0-9][0-9])(?P<function>S|VMR|DNFVI|-vFW)",
            node.label,
        )
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

    for group, data in bsm_list.items():
        for bsm in all_bsms:
            if group == bsm.name:
                data["bsm"] = bsm
                break

    return bsm_list


def cleanup_bsms(server: PyONMS, all_bsms: List[BusinessService]) -> None:
    for bsm in tqdm(all_bsms, desc="Checking for empty BSMs", unit="bsm"):
        if (
            not bsm.application_edges
            and not bsm.child_edges
            and not bsm.ip_services_edges
            and not bsm.reduction_key_edges
        ):
            server.bsm.delete_bsm(bsm.id)


def generate_ip_edge(
    node: dict, service_id: int, friendly_name: str
) -> IPServiceEdgeRequest:
    if node["function"] == "S":
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.CRITICAL),
        )

    elif node["function"] == "DNFVI":
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(
                type="SetTo",
                status=Severity.MAJOR,
            ),
        )

    elif node["function"] == "VMR":
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(
                type="SetTo",
                status=Severity.MINOR,
            ),
        )

    else:
        return IPServiceEdgeRequest(
            friendly_name=friendly_name,
            ip_service_id=service_id,
            map_function=MapFunction(type="SetTo", status=Severity.WARNING),
        )


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
                    if "ICMP" in service.serviceType.name:
                        friendly_name = node["friendly_name"]
                        edge = generate_ip_edge(
                            node=node,
                            service_id=service.id,
                            friendly_name=friendly_name,
                        )
                        new_bsm.update_edge(ip_edge=edge)
    if old_bsm:
        server.bsm.update_bsm(bsm=new_bsm, id=old_bsm.id)
    else:
        server.bsm.create_bsm(new_bsm)
    return group


def process_instance(server: PyONMS, threads: int = 10) -> None:
    server.bsm.reload_bsm_daemon()
    all_bsms = server.bsm.get_bsms()

    bsm_list = get_bsm_list(server=server, all_bsms=all_bsms, threads=threads)

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

    server.bsm.reload_bsm_daemon()
    all_bsms = server.bsm.get_bsms()
    cleanup_bsms(server=server, all_bsms=all_bsms)


def main():
    hostname = os.getenv("hostname")
    username = os.getenv("username")
    password = os.getenv("password")
    if not hostname:
        from instances import instances

        for instance in instances.values():
            hostname = instance["hostname"]
            username = instance["username"]
            password = instance["password"]
            break
        with open(".env", "w") as f:
            f.write(f"hostname={hostname}\n")
            f.write(f"username={username}\n")
            f.write(f"password={password}\n")
    server = PyONMS(hostname=hostname, username=username, password=password)
    process_instance(server, threads=25)


if __name__ == "__main__":
    main()
