# BSM Builder

NOTE: This repo is an example of working with the OpenNMS REST API for building Business Services.
This repo is provided as is.

## Getting Started

* Install Python dependencies.
  * `pip3 install -r requirements.txt`

* Create a `.env` file and set values to connect to your server.
  * `bsm_hostname=http://localhost:8980`)
  * `bsm_username=admin`
  * `bsm_password=admin`

* ALTERNATIVELY, you can set those three values as environment variables instead of creating a `.env` file.

See `bsm_builder.py` for an example.
In this file, there verify the values for `CRITICAL_SERVICES` and `MANUFACTURERS` match values on your nodes.


## Logging

The `bsm_builder.py` script will append logs to a `logs/bsm_topo_YYYY-MM-DD.log` file.
This file can be changed by specifying a full path to a file with the `log_file` environment variable (via `.env`).
If the filename contains the string `DATE`, it will be replaced with the current date in the format `YYYY-MM-DD`.
