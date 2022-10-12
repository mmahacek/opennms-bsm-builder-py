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

* See `bsm_builder.py` for an example.
