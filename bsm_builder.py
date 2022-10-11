# test.py

import concurrent.futures
import re

from typing import List
from tqdm import tqdm

from instances import instances

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


def get_bsm_list(my_server: PyONMS, all_bsms: list):
    nodes = my_server.nodes.get_nodes(
        limit=0, batch_size=100, components=[NodeComponents.IP], threads=25
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


def cleanup_bsms(my_server: PyONMS, all_bsms: List[BusinessService]):
    for bsm in all_bsms:
        if (
            not bsm.application_edges
            and not bsm.child_edges
            and not bsm.ip_services_edges
            and not bsm.reduction_key_edges
        ):
            my_server.bsm.delete_bsm(bsm.id)


def process_instance(my_server: PyONMS):  # noqa: C901
    overall_progress = tqdm(desc="Overall progress", unit="step", total=4)
    all_bsms = my_server.bsm.get_bsms()

    overall_progress.update(1)

    bsm_list = get_bsm_list(my_server, all_bsms)

    overall_progress.update(1)

    with concurrent.futures.ProcessPoolExecutor(max_workers=10) as pool:
        with tqdm(
            total=len(bsm_list.keys()), unit="site", desc="Updating BSM models"
        ) as progress:
            futures = []
            for group, data in bsm_list.items():
                future = pool.submit(
                    process_site, my_server=my_server, group=group, data=data
                )
                future.add_done_callback(lambda p: progress.update())
                futures.append(future)
            for future in futures:
                result = future.result()
            #   devices.append(result)

    my_server.bsm.reload_bsm_daemon()
    overall_progress.update(1)
    overall_progress.set_description(desc="Removing empty services")
    all_bsms = my_server.bsm.get_bsms()
    cleanup_bsms(my_server, all_bsms)
    overall_progress.update(1)
    pass


def process_site(my_server, group, data):  # noqa: C901
    site_bsm = my_server.bsm.find_bsm_name(name=group)
    if site_bsm:
        new_bsm = site_bsm.request()
    else:
        new_bsm = BusinessServiceRequest(name=group)
    new_bsm.add_attribute(Attribute(key="model", value="device"))
    for node in data["nodes"]:
        for ip in node["node"].ipInterfaces:
            if ip.snmpPrimary.value == "P":
                for service in ip.services:
                    if "ICMP" in service.serviceType.name:
                        # friendly_name = f"{group}-{node['instance']}-{node['function']}"
                        friendly_name = node["friendly_name"]
                        if node["function"] == "S":
                            new_bsm.update_edge(
                                ip_edge=IPServiceEdgeRequest(
                                    friendly_name=friendly_name,
                                    ip_service_id=service.id,
                                    map_function=MapFunction(
                                        type="SetTo", status=Severity.CRITICAL
                                    ),
                                )
                            )
                        elif node["function"] == "DNFVI":
                            new_bsm.update_edge(
                                ip_edge=IPServiceEdgeRequest(
                                    friendly_name=friendly_name,
                                    ip_service_id=service.id,
                                    map_function=MapFunction(
                                        type="SetTo",
                                        status=Severity.MAJOR,
                                    ),
                                )
                            )
                        elif node["function"] == "VMR":
                            new_bsm.update_edge(
                                ip_edge=IPServiceEdgeRequest(
                                    friendly_name=friendly_name,
                                    ip_service_id=service.id,
                                    map_function=MapFunction(
                                        type="SetTo",
                                        status=Severity.MINOR,
                                    ),
                                )
                            )
                        else:
                            new_bsm.update_edge(
                                ip_edge=IPServiceEdgeRequest(
                                    friendly_name=friendly_name,
                                    ip_service_id=service.id,
                                    map_function=MapFunction(
                                        type="SetTo", status=Severity.WARNING
                                    ),
                                )
                            )
    if site_bsm:
        new_site_bsm = my_server.bsm.update_bsm(bsm=new_bsm, id=site_bsm.id)
    else:
        new_site_bsm = my_server.bsm.create_bsm(new_bsm)
    data["new"] = new_site_bsm


if __name__ == "__main__":  # noqa: C901
    for server in instances.values():
        my_server = PyONMS(
            hostname=server["hostname"],
            username=server["username"],
            password=server["password"],
        )
        process_instance(my_server)
