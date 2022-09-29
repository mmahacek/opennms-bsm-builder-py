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
            "MI_(?P<org>.*)-(?P<host>.*)(?P<instance>0[1-2])(?P<function>S|VMR|DNFVI)",
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
    all_bsms = my_server.bsm.get_bsms()

    bsm_list = get_bsm_list(all_bsms)

    site_bsms = {}

    used_services = []
    with tqdm(
        unit="site", desc="Updating BSM models", total=len(bsm_list.keys())
    ) as pbar:
        for group, data in bsm_list.items():
            pbar.set_description(f"Updating {group} BSM model")
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
            virtual_bsm = my_server.bsm.find_bsm_name(name=f"{group}-VNF")
            if virtual_bsm:
                vnf_bsm = virtual_bsm.request()
            else:
                vnf_bsm = BusinessServiceRequest(name=f"{group}-VNF")
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

                            if node["function"] == "S":
                                new_bsm.update_edge(
                                    ip_edge=IPServiceEdgeRequest(
                                        friendly_name=friendly_name,
                                        ip_service_id=service.id,
                                    )
                                )
                                used_services.append(service)
                            else:
                                vnf_bsm.update_edge(
                                    ip_edge=IPServiceEdgeRequest(
                                        friendly_name=friendly_name,
                                        ip_service_id=service.id,
                                    )
                                )
                                used_services.append(service)
            if virtual_bsm:
                new_vnf_bsm = my_server.bsm.update_bsm(bsm=vnf_bsm, id=virtual_bsm.id)
            else:
                new_vnf_bsm = my_server.bsm.create_bsm(vnf_bsm)
            data["new"] = new_vnf_bsm
            if new_vnf_bsm.id not in [bsm.id for bsm in all_bsms]:
                all_bsms.append(new_vnf_bsm)
            child = [bsm for bsm in all_bsms if bsm.id == new_vnf_bsm.id]
            if child:
                new_bsm.child_edges.append(
                    ChildEdgeRequest(
                        child_id=child[0].id, map_function=MapFunction("Decrease")
                    )
                )
            else:
                new_bsm.child_edges.append(
                    ChildEdgeRequest(
                        child_id=new_vnf_bsm.id, map_function=MapFunction("Decrease")
                    )
                )
            if switch_bsm:
                new_parent_bsm = my_server.bsm.update_bsm(bsm=new_bsm, id=switch_bsm.id)
            else:
                new_parent_bsm = my_server.bsm.create_bsm(new_bsm)
            data["new"] = new_parent_bsm
            if new_parent_bsm not in [bsm.id for bsm in all_bsms]:
                all_bsms.append(new_parent_bsm)
            site_bsm_update = site_bsms[data["parent"]].request()
            site_bsm_update.update_edge(
                child_edge=ChildEdgeRequest(
                    child_id=new_parent_bsm.id, map_function=MapFunction(type="Ignore")
                )
            )
            site_bsms[data["parent"]] = my_server.bsm.update_bsm(
                site_bsms[data["parent"]].id, site_bsm_update
            )
            pbar.update(1)
    my_server.bsm.reload_bsm_daemon()
pass
