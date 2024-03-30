#!/bin/bash

command1="python3 04_data_analysis/02_protocol/build_count_frequency_histo.py -i 03_preprocessing/04_product -o 04_data_analysis/04_product"

eval "$command1"

command2="python3 04_data_analysis/02_protocol/bootstrapping.py -i 03_preprocessing/04_product -o 04_data_analysis/04_product"

eval "$command2"
