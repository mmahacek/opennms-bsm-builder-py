# bsm_builder.py

import concurrent.futures
import logging
import os
import time

from tqdm import tqdm

from pyonms import PyONMS

import bsm_builder

from instances import instances

BATCH_PATH = os.environ.get("log_path", "./logs/bsm_topo_DATE.log").replace(
    "DATE", time.strftime("%Y-%m-%d")
)

batch_formatter = logging.Formatter(
    "%(asctime)s %(levelname)s [main] (Thread-%(thread)s-%(funcName)s) %(message)s"
)
batch_logger = logging.getLogger("bsm_batch")
batch_logger.setLevel(logging.DEBUG)
bh = logging.FileHandler(BATCH_PATH)
bh.setFormatter(batch_formatter)
bh.setLevel(logging.DEBUG)

batch_logger.addHandler(bh)


def main_thread(threads: int = 10, fresh: bool = False):
    if len(instances) < threads:
        instance_threads = len(instances)
    else:
        instance_threads = threads
    with concurrent.futures.ProcessPoolExecutor(max_workers=instance_threads) as pool:
        with tqdm(
            total=len(instances),
            unit="instances",
            desc="Processing instances",
        ) as progress:
            futures = []
            for instance_name, instance in instances.items():
                hostname = instance["hostname"]
                username = instance["username"]
                password = instance["password"]
                server = PyONMS(
                    hostname=hostname,
                    username=username,
                    password=password,
                    name=instance_name,
                )
                future = pool.submit(
                    process_instance,
                    server=server,
                    fresh=fresh,
                    threads=threads,
                )
                future.add_done_callback(lambda p: progress.update())
                futures.append(future)
            for future in futures:
                future.result()


def process_instance(server: PyONMS, fresh: bool = False, threads: int = 10):
    batch_logger.info(f"Starting {server.name}")
    bsm_builder.instance_builder(server=server, fresh=fresh, threads=threads)
    batch_logger.info(f"Completed {server.name}")


def main(threads: int = 10, fresh: bool = False):
    for instance_name, instance in instances.items():
        hostname = instance["hostname"]
        username = instance["username"]
        password = instance["password"]
        server = PyONMS(
            hostname=hostname, username=username, password=password, name=instance_name
        )

        bsm_builder.instance_builder(
            server=server,
            fresh=fresh,
            threads=threads,
        )


if __name__ == "__main__":
    batch_logger.info("Starting BSM batch")
    main_thread(threads=25, fresh=False)
    batch_logger.info("Completed BSM batch")
