import subprocess as sp
import os
import argparse
import shutil
import json
import threading

#
# Image SBOM generation script
#
# This script performs generates SBOMs for docker images using Trivy and Syft tools. It takes a JSON file containing a
# list of Docker images and versions as input, and generates CycloneDX 1.5 and SPDX 2.2 formatted SBOM
# for the specified number of versions per image.
#
# Usage:
#   python script_name.py -i input_file.json -o output_directory
#
# Command Line Options:
#   -i or --input: Path to the input JSON file containing Docker image information.
#   -o or --output: Path to the output directory for generated SBOMs.
#   -v or --versions: Number of versions per image to generate SBOMs for. Default is 10.
#
# Results are saved as:
#   sbom_[gen tool]:[gen tool versions]_[image name]:[image version]_[spec]:[spec version].json
#
# This script assumes that Trivy and Syft are installed and are available in the system PATH.
#
# Dependencies:
#   - Trivy v0.49.0 (https://github.com/aquasecurity/trivy)
#   - Syft v0.102.0 (https://github.com/anchore/syft)
#
# Author:
#   Eric O'Donoghue and ChatGPT
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

def extract_versions(versions, num_elements):
    if len(versions) <= num_elements:
        return versions
    step = len(versions) // (num_elements - 1)
    return [versions[i] for i in range(0, len(versions), step)]

def run_trivy_cdx(image_name, image_version, output_path):
    print(f"start trivy {image_name}:{image_version}")
    
    # trivy image -f cyclonedx -o [gen tool]:[gen tool version]_[image name]:[image version]_[spec]:[spec version].json [name]:[version]
    cmd = ['trivy', 'image', '-f', 'cyclonedx', '-o', f"{output_path}CDX1.5/sbom_trivy:0.49.0_{image_name}:{image_version.replace('_', '-')}_cdx:1.5.json", image_name + ":" + image_version]
    sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')

    print("finish trivy")

def kick_off_trivy_cdx(images, versions, output):
    for image in images["images"]:
        print(f"### {image['name']} ###")
        selected_versions = extract_versions(image["versions"], versions)
        for version in selected_versions:
            if f"sbom_trivy:0.49.0_{image}:{version.replace('_', '-')}_cdx:1.5.json" in os.listdir(f"{output}trivy_g/CDX1.5"):
                print(f"skipping {image}:{version} - syft SPDX2.2 SBOM present\n")
                continue
            run_trivy_cdx(image["name"], version, output + "trivy_g/")
            print()
        clear_images()
        print('\n\n')

def run_trivy_spdx(image_name, image_version, output_path):
    print(f"start trivy {image_name}:{image_version}")

    # trivy image -f spdx-json -o [gen tool]-[gen tool version]_[image name]-[image version]_[spec]-[spec version].json [name]:[version]
    cmd = ['trivy', 'image', '-f', 'spdx-json', '-o', f"{output_path}SPDX2.2/sbom_trivy:0.49.0_{image_name}:{image_version.replace('_', '-')}_spdx:2.2_.spdx.json",image_name + ":" + image_version]
    sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')

    print("finish trivy")

def kick_off_trivy_spdx(images, versions, output):
    for image in images["images"]:
        print(f"### {image['name']} ###")
        selected_versions = extract_versions(image["versions"], versions)
        for version in selected_versions:
            if f"sbom_trivy:0.49.0_{image}:{version.replace('_', '-')}_spdx:2.2_.spdx.json" in os.listdir(f"{output}trivy_g/SPDX2.2"):
                print(f"skipping {image}:{version} - syft SPDX2.2 SBOM present\n")
                continue
            run_trivy_spdx(image["name"], version, output + "trivy_g/")
            print()
        clear_images()
        print('\n\n')


def run_syft_cdx(image_name, image_version, output_path):
    print(f"start syft {image_name}:{image_version}")

    # syft [name]:[version] -o cyclonedx-json
    cmd = ['syft', f"{image_name}:{image_version}", '-o', 'cyclonedx-json@1.5']
    results = sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(f"{output_path}CDX1.5/sbom_syft:0.102.0_{image_name}:{image_version.replace('_', '-')}_cdx:1.5.json", "w")
    f.write(results)
    f.close()

    print("finish syft")

def kick_off_syft_cdx(images, versions, output):
    for image in images["images"]:
        print(f"### {image['name']} ###")
        selected_versions = extract_versions(image["versions"], versions)
        for version in selected_versions:
            if f"sbom_syft:0.102.0_{image}:{version.replace('_', '-')}_cdx:1.5.json" in os.listdir(f"{output}syft/CDX1.5"):
                print(f"skipping {image}:{version} - syft SPDX2.2 SBOM present\n")
                continue
            run_syft_cdx(image["name"], version, output + "syft/")
            print()
        clear_images()
        print('\n\n')

def run_syft_spdx(image_name, image_version, output_path):
    print(f"start syft {image_name}:{image_version}")

    # syft [name]:[version] -o spdx-json@2.2
    cmd = ['syft', f"{image_name}:{image_version}", '-o', 'spdx-json@2.2']
    results = sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(f"{output_path}SPDX2.2/sbom_syft:0.102.0_{image_name}:{image_version.replace('_', '-')}_spdx:2.2_.spdx.json", "w")
    f.write(results)
    f.close()

    print("finish syft")

def kick_off_syft_spdx(images, versions, output):
    for image in images["images"]:
        print(f"### {image['name']} ###")
        selected_versions = extract_versions(image["versions"], versions)
        for version in selected_versions:
            if f"sbom_syft:0.102.0_{image}:{version.replace('_', '-')}_spdx:2.2_.spdx.json" in os.listdir(f"{output}syft/SPDX2.2/"):
                print(f"skipping {image}:{version} - syft SPDX2.2 SBOM present\n")
                continue
            run_syft_spdx(image["name"], version, output + "syft/")
            print()
        clear_images()
        print('\n\n')


def clear_images():
    print("start clear images")

    # docker image prune -a
    cmd = ['docker', 'image', 'prune', '-af']
    sp.run(args=cmd, stdout=sp.PIPE, stderr=sp.PIPE)

    print("finish clear images")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument("-v", "--versions", dest="versions", default="", help="")
    parser.add_argument("-c", "--clear", dest="clear", default="", help="")

    args = parser.parse_args()
    _input = args.input
    output = args.output + "/"
    versions = int(args.versions)
    clear = args.clear

    if clear == "true":
        clear_dir(output + "trivy_g/CDX1.5")
        clear_dir(output + "trivy_g/SPDX2.2")
        clear_dir(output + "syft/CDX1.5")
        clear_dir(output + "syft/SPDX2.2")

    with open(_input, "r") as file:
        images = json.load(file)

    trivy_cdx_thread = threading.Thread(target=kick_off_trivy_cdx, args=(images, versions, output))
    trivy_spdx_thread = threading.Thread(target=kick_off_trivy_spdx, args=(images, versions, output))
    syft_cdx_thread = threading.Thread(target=kick_off_syft_cdx, args=(images, versions, output))
    syft_spdx_thread = threading.Thread(target=kick_off_syft_spdx, args=(images, versions, output))

    trivy_cdx_thread.start()
    trivy_spdx_thread.start()
    syft_cdx_thread.start()
    syft_spdx_thread.start()

    trivy_cdx_thread.join()
    trivy_spdx_thread.join()
    syft_cdx_thread.join()
    syft_spdx_thread.join()

main()
