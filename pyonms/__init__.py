# __init__.py

import pyonms.dao.nodes
import pyonms.dao.business_services


class PyONMS:
    def __init__(self, hostname: str, username: str, password: str):
        self.hostname = hostname
        args = {
            "hostname": hostname,
            "username": username,
            "password": password,
        }
        self.bsm = pyonms.dao.business_services.BSMAPI(args)
        self.nodes = pyonms.dao.nodes.NodeAPI(args)

    def __repr__(self):
        return self.hostname
