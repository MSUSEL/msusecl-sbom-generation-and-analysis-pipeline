import subprocess as sp
import os
import argparse
import shutil

#
# This Python script runs sbomqs on a repository of SBOMs.
# It takes SBOM files as input, runs sbomqs on each file, and saves the results in JSON format.
#
# Usage:
# python sbomqs_runner.py -i /path/to/sbom/files -o /output/directory -gt gen_tool_name -s spec_version
#
# Arguments:
# - i, --input: Path to the directory containing SBOM files.
# - o, --output: Path to the output directory where sbomqs results will be saved.
# - gt, --gen_tool: Name of the generator tool used to create the SBOM files.
# - s, --spec: Version of the SBOM specification used.
#
# Results are saved as:
#   sbomqs-results_sbom_[gen tool]:[gen tool versions]_[image name]:[image version]_[spec]:[spec version].json
#
# Note:
# This script assumes that sbomqs is installed and available in the system PATH.
# sbomqs is a compliance and quality scanner for SBOMs, it can be found at https://github.com/interlynk-io/sbomqs.
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


def run_sbomqs(sbom_path, output_name, output_path):
    print("start sbomqs")
    sbomqs_results = sp.run(['sbomqs', 'score', sbom_path, '--json'], stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(f"{output_path}{output_name}.json", "w")
    f.write(sbomqs_results)
    f.close()
    print("finish sbomqs")


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
        print(f"Clearing {output}/{gen_tool}/{spec}/sbomqs\n\n")
        clear_dir(f"{output}/{gen_tool}/{spec}/sbomqs")

    for filename in os.listdir(f"{_input}{gen_tool}/{spec}"):
        print(f"### {filename} ###")
        file_path = os.path.join(f"{_input}{gen_tool}/{spec}/", filename)
        name_without_extension, _ = os.path.splitext(filename)
        if f"sbomqs-results_{name_without_extension}.json" in os.listdir(f"{output}/{gen_tool}/{spec}/sbomqs"):
            print(f"skipping {name_without_extension} - sbomqs results present\n")
            continue

        run_sbomqs(file_path, "sbomqs-results_" + name_without_extension, f"{output}/{gen_tool}/{spec}/sbomqs/")
        print()


main()




