#!/bin/bash

command1="python3 02_evaluate/02_protocol/trivy_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s CDX1.5 -c false &"
command2="python3 02_evaluate/02_protocol/trivy_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s SPDX2.2 -c false &"
command3="python3 02_evaluate/02_protocol/trivy_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s CDX1.5 -c false &"
command4="python3 02_evaluate/02_protocol/trivy_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s SPDX2.2 -c false &"

eval "$command1"
eval "$command2"
eval "$command3"
eval "$command4"

command4="python3 02_evaluate/02_protocol/grype_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s CDX1.5 -c false &"
command5="python3 02_evaluate/02_protocol/grype_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s SPDX2.2 -c false &"
command6="python3 02_evaluate/02_protocol/grype_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s CDX1.5 -c false &"
command7="python3 02_evaluate/02_protocol/grype_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s SPDX2.2 -c false &"

eval "$command4"
eval "$command5"
eval "$command6"
eval "$command7"

command8="python3 02_evaluate/02_protocol/sbomqs_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s CDX1.5 -c false &"
command9="python3 02_evaluate/02_protocol/sbomqs_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s SPDX2.2 -c false &"
command10="python3 02_evaluate/02_protocol/sbomqs_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s CDX1.5 -c false &"
command11="python3 02_evaluate/02_protocol/sbomqs_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s SPDX2.2 -c false &"

eval "$command8"
eval "$command9"
eval "$command10"
eval "$command11"

command12="python3 02_evaluate/02_protocol/cve_bin_tool_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s CDX1.5 -c false"
command13="python3 02_evaluate/02_protocol/cve_bin_tool_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt trivy_g -s SPDX2.2 -c false &"
command14="python3 02_evaluate/02_protocol/cve_bin_tool_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s CDX1.5 -c false &"
command15="python3 02_evaluate/02_protocol/cve_bin_tool_runner.py -i 01_acquisition/04_product -o 02_evaluate/04_product -gt syft -s SPDX2.2 -c false &"

eval "$command12"
eval "$command13"
eval "$command14"
eval "$command15"



























