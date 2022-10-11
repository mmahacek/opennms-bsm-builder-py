# BSM Builder

NOTE: This repo is an example of working with the OpenNMS REST API for building Business Services.
This repo is provided as is.

## Getting Started

* Install Python dependencies
  * `pip3 install -r requirements.txt`

* Create a `instances.py` file to define your list of servers to process.
  * The file should have the following structure, repeating for each server instance to process:
```py
instances = {
    "horizon_1": {
        "hostname": "http://localhost:8980/opennms/",
        "username": "admin",
        "password": "admin",
    },
}
```
* See `bsm_builder.py` for an example.
