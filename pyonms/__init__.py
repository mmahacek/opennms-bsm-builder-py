# __init__.py

"""
.. include:: ../README.md
"""

from urllib.parse import urlsplit

import pyonms.dao.business_services
import pyonms.dao.nodes


class PyONMS:
    """OpenNMS Instance object"""

    def __init__(self, hostname: str, username: str, password: str, name: str = None):
        """Attributes:
            hostname (str): OpenNMS URL
            username (str): Username
            password (str): Password
            name (str): Instance name
        Returns:
            `PyONMS` object
        """
        self.hostname = hostname
        args = {
            "hostname": hostname,
            "username": username,
            "password": password,
        }
        if name:
            self.name = name
            args["name"] = name
        else:
            self.name = urlsplit(hostname).netloc.split(":")[0]
            args["name"] = self.name
        self.bsm = pyonms.dao.business_services.BSMAPI(args)
        """`pyonms.dao.business_services.BSMAPI` endpoint"""
        self.nodes = pyonms.dao.nodes.NodeAPI(args)
        """`pyonms.dao.nodes.NodeAPI` endpoint"""

    def __repr__(self):
        return self.hostname
