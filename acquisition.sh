#!/bin/bash

command1="python3 01_acquisition/02_protocol/generate_sboms.py -i 01_acquisition/01_input/docker-images.json -o 01_acquisition/04_product -v 25 -c true"

eval "$command1"
