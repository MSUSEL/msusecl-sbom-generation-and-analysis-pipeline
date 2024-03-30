import subprocess as sp
import os
import argparse
import shutil


#
# This script performs static analysis on software bill of materials (SBOM) files using cve-bin-tool.
# It takes SBOM files as input, runs cve-bin-tool on each file, and saves the results in JSON format.
#
# Usage:
# python cve_bin_tool_runner.py -i /path/to/sbom/files -o /output/directory -gt gen_tool_name -s spec_version
#
# Arguments:
# - i, --input: Path to the directory containing SBOM files.
# - o, --output: Path to the output directory where cve-bin-tool results will be saved.
# - gt, --gen_tool: Name of the generator tool used to create the SBOM files.
# - s, --spec: Version of the SBOM specification used.
#
# Results are saved as:
#   cve-bin-tool-results_sbom_[gen tool]:[gen tool versions]_[image name]:[image version]_[spec]:[spec version].json
# Note:
# This script assumes that cve-bin-tool is installed and available in the system PATH.
# cve-bin-tool is a free, open source tool to help you find known vulnerabilities in software, and it can be found at https://github.com/intel/cve-bin-tool/tree/main.
#

def clear_dir(output):
    try:
        for filename in os.listdir(output):
            file_path = os.path.join(output, filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
    except Exception as e:
        print(f"Failed to clear directory '{output}': {str(e)}")


def run_cve_bin_tool(sbom_path, output_name, output_path, spec):
    print("start cve-bin-tool")
    # cve-bin-tool --disable-version-check --nvd-api-key 1da8de83-0e00-468f-ad6f-00fd0f351c18 --sbom cyclonedx -f json --output  --sbom-file
    cmd = ['cve-bin-tool', '--disable-version-check', '--nvd-api-key', '1da8de83-0e00-468f-ad6f-00fd0f351c18', '--sbom', spec, '-f', 'json', '--output', output_path + output_name + ".json", '--sbom-file', sbom_path]
    sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    print("finish cve-bin-tool")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument('-gt', '--gen_tool', dest='gen_tool', default="", help="")
    parser.add_argument('-s', '--spec', dest='spec', default="", help="")
    parser.add_argument('-c', '--clear', dest='clear', default="", help="")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output
    gen_tool = args.gen_tool
    spec = args.spec
    clear = args.clear

    if clear == "true":
        print(f"Clearing {output}/{gen_tool}/{spec}/cve_bin_tool\n\n")
        clear_dir(f"{output}/{gen_tool}/{spec}/cve_bin_tool")

    if spec == "CDX1.5":
        _spec = "cyclonedx"
    else:
        _spec = "spdx"

    for filename in os.listdir(f"{_input}{gen_tool}/{spec}"):
        print(f"### {filename} ###")
        file_path = os.path.join(f"{_input}{gen_tool}/{spec}/", filename)
        name_without_extension, _ = os.path.splitext(filename)
        if f"cve-bin-tool-results_{name_without_extension}.json" in os.listdir(f"{output}/{gen_tool}/{spec}/cve_bin_tool"):
            print(f"skipping {name_without_extension} - cve-bin-tool results present\n")
            continue
        run_cve_bin_tool(file_path, "cve-bin-tool-results_" + name_without_extension, f"{output}/{gen_tool}/{spec}/cve_bin_tool/", _spec)
        print()


main()


