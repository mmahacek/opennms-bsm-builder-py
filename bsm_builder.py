# test.py

import os
import re

from dotenv import load_dotenv
from tqdm import tqdm

from pyonms import PyONMS
from pyonms.dao.nodes import NodeComponents
from pyonms.models.business_service import (
    BusinessServiceRequest,
    IPServiceEdgeRequest,
    ChildEdgeRequest,
    MapFunction,
    ReduceFunction,
    Attribute,
    Severity,
)

load_dotenv()

my_server = PyONMS(
    hostname=os.getenv("hostname"),
    username=os.getenv("username"),
    password=os.getenv("password"),
)


def get_bsm_list(all_bsms):
    nodes = my_server.nodes.get_nodes(
        limit=0, batch_size=100, components=[NodeComponents.IP]
    )

    bsm_list = {}
    for node in nodes:
        match = re.match(
            "MI_(?P<org>.*)-(?P<host>.*)(?P<instance>[0-9][0-9])(?P<function>S|VMR|DNFVI|-vFW)",
            node.label,
        )
        if match:
            payload = {
                "node": node,
                "instance": match.group("instance"),
                "function": match.group("function"),
            }
            host_group = f'{match.group("host")}{match.group("instance")}'
            if bsm_list.get(host_group):
                bsm_list[host_group]["nodes"].append(payload)
            else:
                bsm_list[host_group] = {
                    "nodes": [payload],
                    "instance": match.group("instance"),
                    "parent": match.group("host"),
                }
            # print(match.groups())

    for group, data in bsm_list.items():
        for bsm in all_bsms:
            if group == bsm.name:
                data["bsm"] = bsm
                break

    return bsm_list


if __name__ == "__main__":  # noqa: C901
    overall_progress = tqdm(desc="Overall progress", unit="step", total=3)
    all_bsms = my_server.bsm.get_bsms()

    overall_progress.update(1)

    bsm_list = get_bsm_list(all_bsms)

    overall_progress.update(1)

    site_bsms = {}
    used_services = []
    with tqdm(
        unit="site", desc="Updating BSM models", total=len(bsm_list.keys())
    ) as progress_bar:
        for group, data in bsm_list.items():
            progress_bar.set_description(f"Updating {group} BSM model")
            if not site_bsms.get(data["parent"]):
                site_bsms[data["parent"]] = my_server.bsm.find_bsm_name(
                    name=data["parent"]
                )
            if not site_bsms.get(data["parent"]):
                site_bsms[data["parent"]] = my_server.bsm.create_bsm(
                    BusinessServiceRequest(name=data["parent"])
                )
            switch_bsm = my_server.bsm.find_bsm_name(name=group)
            if switch_bsm:
                new_bsm = switch_bsm.request()
            else:
                new_bsm = BusinessServiceRequest(name=group)
            new_bsm.add_attribute(Attribute(key="site", value=data["parent"]))
            new_bsm.add_attribute(Attribute(key="model", value="device"))
            for node in data["nodes"]:
                for ip in node["node"].ipInterfaces:
                    for service in ip.services:
                        if (
                            service not in used_services
                            and "ICMP" in service.serviceType.name
                        ):
                            friendly_name = f"{group}{node['function']}-{service.serviceType.name}".replace(
                                "Flexware-", ""
                            )
                            friendly_name = (
                                node["function"]
                                .replace("-", "")
                                .replace("S", "SAOS")
                                .replace("VMR", "Vyatta")
                                .replace("vFW", "Velo")
                            )

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
                                used_services.append(service)
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
                                used_services.append(service)
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
                                used_services.append(service)
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
                                used_services.append(service)
            if switch_bsm:
                new_parent_bsm = my_server.bsm.update_bsm(bsm=new_bsm, id=switch_bsm.id)
            else:
                new_parent_bsm = my_server.bsm.create_bsm(new_bsm)
            data["new"] = new_parent_bsm
            if new_parent_bsm not in [bsm.id for bsm in all_bsms]:
                all_bsms.append(new_parent_bsm)
            site_bsm_update = site_bsms[data["parent"]].request()
            site_bsm_update.add_attribute(Attribute(key="site", value=data["parent"]))
            site_bsm_update.add_attribute(Attribute(key="model", value="site"))
            site_bsm_update.reduce_function = ReduceFunction(type="HighestSeverity")
            site_bsm_update.update_edge(
                child_edge=ChildEdgeRequest(
                    child_id=new_parent_bsm.id,
                    map_function=MapFunction(type="Decrease"),
                )
            )
            site_bsms[data["parent"]] = my_server.bsm.update_bsm(
                site_bsms[data["parent"]].id, site_bsm_update
            )
            progress_bar.update(1)
    my_server.bsm.reload_bsm_daemon()
overall_progress.update(1)
pass
