#!/bin/bash

command1="python3 03_preprocessing/02_protocol/build_dataframe.py -i 01_acquisition/04_product/syft/CDX1.5 -o 03_preprocessing/04_product -gt syft -s CDX1.5"
command2="python3 03_preprocessing/02_protocol/build_dataframe.py -i 01_acquisition/04_product/syft/SPDX2.2 -o 03_preprocessing/04_product -gt syft -s SPDX2.2"
command3="python3 03_preprocessing/02_protocol/build_dataframe.py -i 01_acquisition/04_product/trivy_g/CDX1.5 -o 03_preprocessing/04_product -gt trivy_g -s CDX1.5"
command4="python3 03_preprocessing/02_protocol/build_dataframe.py -i 01_acquisition/04_product/trivy_g/SPDX2.2 -o 03_preprocessing/04_product -gt trivy_g -s SPDX2.2"

eval "$command1"
eval "$command2"
eval "$command3"
eval "$command4"

command5="python3 03_preprocessing/02_protocol/merge_dataframes.py -i 03_preprocessing/04_product -o 03_preprocessing/04_product"

eval "$command5"