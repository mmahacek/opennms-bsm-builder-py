# dao.business_services.py

# cspell:ignore snmpinterfaces, ipinterfaces

import concurrent.futures
from typing import List, Optional

from tqdm import tqdm

from pyonms.dao import Endpoint
import pyonms.models.business_service
import pyonms.models.exceptions


class BSMAPI(Endpoint):
    def __init__(self, kwargs):
        super().__init__(**kwargs)
        self.url = self.base_v2 + "business-services"
        self._init_cache()

    def _init_cache(self):
        self.cache = {}
        self.cache_name = {}

    def get_bsm(
        self, id: int
    ) -> Optional[pyonms.models.business_service.BusinessService]:
        record = self._get(uri=f"{self.url}/{id}")
        if record is not None:
            bsm = self._process_bsm(record)
            self.cache[bsm.id] = bsm
            self.cache_name[bsm.name] = bsm.id
            return bsm
        else:
            return None

    def _get_bsm_ids(
        self,
    ) -> dict:
        response = self._get(uri=self.url)
        if response.get("business-services"):
            return response
        else:
            return {"business-services": []}

    def get_bsms(
        self, threads: int = 10
    ) -> List[Optional[pyonms.models.business_service.BusinessService]]:
        service_list = []
        services = self._get_bsm_ids()

        with concurrent.futures.ProcessPoolExecutor(max_workers=threads) as pool:
            with tqdm(
                total=len(services["business-services"]),
                unit="business-service",
                desc=f"Getting {self.name} Business Services",
            ) as progress:
                futures = []
                for service_url in services["business-services"]:
                    future = pool.submit(
                        self.get_bsm,
                        id=service_url[26:],
                    )
                    future.add_done_callback(lambda p: progress.update())
                    futures.append(future)
                for future in futures:
                    bsm = future.result()
                    self.cache[bsm.id] = bsm
                    self.cache_name[bsm.name] = bsm.id
                    service_list.append(bsm)

        return service_list

    def find_bsm_name(
        self, name: str, cache_only: bool = False
    ) -> Optional[pyonms.models.business_service.BusinessService]:
        if self.cache_name.get(name):
            return self.cache[self.cache_name[name]]
        elif cache_only:
            return None
        else:
            services = self._get(uri=self.url)
            for service_url in services.get("business-services", []):
                service_record = self._get(uri=f"{self.hostname}{service_url}")
                if service_record["name"] == name:
                    return self._process_bsm(service_record)
        return None

    def _process_bsm(
        self, data: dict
    ) -> pyonms.models.business_service.BusinessService:
        data["ip_services_edges"] = data.get("ip-service-edges", [])
        data["reduction_key_edges"] = data.get("reduction-key-edges", [])
        data["child_edges"] = data.get("child-edges", [])
        data["application_edges"] = data.get("application-edges", [])
        data["parent_services"] = data.get("parent-services", [])
        data["reduce_function"] = data.get("reduce-function", [])
        data["operational_status"] = data.get("operational-status", [])
        del data["operational-status"]
        del data["ip-service-edges"]
        del data["reduction-key-edges"]
        del data["child-edges"]
        del data["application-edges"]
        del data["parent-services"]
        del data["reduce-function"]
        business_service = pyonms.models.business_service.BusinessService(**data)
        return business_service

    def reload_bsm_daemon(self) -> None:
        self._post(uri=f"{self.url}/daemon/reload", json={})

    def create_bsm(
        self, bsm: pyonms.models.business_service.BusinessServiceRequest
    ) -> None:
        response = self._post(uri=self.url, json=bsm.to_dict())
        if "constraint [bsm_service_name_key]" in response:
            raise pyonms.models.exceptions.DuplicateEntityError(bsm.name, bsm)

    def update_bsm(
        self, id: int, bsm: pyonms.models.business_service.BusinessServiceRequest
    ):
        self._put(uri=f"{self.url}/{id}", json=bsm.to_dict())  # noqa: W0612

    def delete_bsm(self, bsm: pyonms.models.business_service.BusinessService) -> None:
        self._delete(uri=f"{self.url}/{bsm.id}")
        if self.cache.get(bsm.id):
            del self.cache[bsm.id]
        if self.cache_name.get(bsm.name):
            del self.cache_name[bsm.name]
