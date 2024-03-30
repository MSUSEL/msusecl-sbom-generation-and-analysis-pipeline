import pandas as pd
import os
import argparse
import json

#
# Python script for processing vulnerability data from Trivy, Grype, and SBOMQS tools on SBOMs.
#
# Command line arguments:
# --input (-i): Path to the folder containing SBOMs in JSON format.
# --output (-o): Path to the folder where the compiled results CSV file will be saved.
# --gen_tool (-gt): The name of the generation tool used to create the SBOMs.
# --spec (-s): The specification version of the SBOMs.
#
# Results are saved in a CSV file:
# "[output]/compiled_results_for_sboms_[gen_tool]_[spec].csv"
#

schema = {
    'target': [],
    'target_version': [],
    'gen_tool': [],
    'gen_tool_version': [],
    'spec': [],
    'num_components': [],
    'trivy_total_vuls': [],
    'trivy_none_vuls': [],
    'trivy_low_vuls': [],
    'trivy_medium_vuls': [],
    'trivy_high_vuls': [],
    'trivy_critical_vuls': [],
    'trivy_vuls': [],
    'grype_total_vuls': [],
    'grype_none_vuls': [],
    'grype_low_vuls': [],
    'grype_medium_vuls': [],
    'grype_high_vuls': [],
    'grype_critical_vuls': [],
    'grype_vuls': [],
    'cve_bin_tool_total_vuls': [],
    'cve_bin_tool_none_vuls': [],
    'cve_bin_tool_low_vuls': [],
    'cve_bin_tool_medium_vuls': [],
    'cve_bin_tool_high_vuls': [],
    'cve_bin_tool_critical_vuls': [],
    'cve_bin_tool_vuls': [],
}

def process_trivy_data(gen_tool, spec, name):
    path = f"02_evaluate/04_product/{gen_tool}/{spec}/trivy_a/trivy_a-results_{name}.json"
    vul_counts = {'total': -1, 'none': -1, 'low': -1, 'medium': -1, 'high': -1, 'critical': -1}
    try:
        with open(path, 'r') as file:
            try:
                data = json.load(file)
            except:
                #print(f"Error opening {path} trivy reporting 0 vulnerabilities for this SBOM")
                return vul_counts, -1
    except:
        #print(f"Error opening {path} trivy reporting 0 vulnerabilities for this SBOM")
        return vul_counts, -1

    vul_counts = {'total':0, 'none':0, 'low':0, 'medium':0, 'high':0, 'critical':0}
    if "Results" in data:
        for entry in data["Results"]:
            if "Vulnerabilities" in entry:
                vul_counts['total'] += len(entry["Vulnerabilities"])

    vuls = []
    if "Results" in data:
        for entry in data["Results"]:
            if "Vulnerabilities" in entry:
                for vulnerability in entry["Vulnerabilities"]:
                    severity = 0
                    if "CVSS" in vulnerability:
                        if "nvd" in vulnerability["CVSS"]:
                            if "V3Score" in vulnerability["CVSS"]["nvd"]:
                                severity = vulnerability["CVSS"]["nvd"]["V3Score"]
                    if severity == 0:
                        vul_counts['none'] += 1
                    elif 0.1 <= severity <= 3.9:
                        vul_counts['low'] += 1
                    elif 4.0 <= severity <= 6.9:
                        vul_counts['medium'] += 1
                    elif 7.0 <= severity <= 8.9:
                        vul_counts['high'] += 1
                    elif 9.0 <= severity <= 10.0:
                        vul_counts['critical'] += 1

                    vuls.append(f"{vulnerability['VulnerabilityID']}:{severity}")

    return vul_counts, vuls

def process_grype_data(gen_tool, spec, name):
    path = f"02_evaluate/04_product/{gen_tool}/{spec}/grype/grype-results_{name}.json"
    vul_counts = {'total': -1, 'none': -1, 'low': -1, 'medium': -1, 'high': -1, 'critical': -1}
    try:
        with open(path, 'r') as file:
            try:
                data = json.load(file)
            except:
                #print(f"Error opening {path} grype reporting 0 vulnerabilities for this SBOM")
                return vul_counts, -1
    except:
        #print(f"Error opening {path} grype reporting 0 vulnerabilities for this SBOM")
        return vul_counts, -1

    vul_counts = {'total':0, 'none':0, 'low':0, 'medium':0, 'high':0, 'critical':0}
    vuls = []
    if "matches" in data:
        vul_counts['total'] += len(data["matches"])
        for entry in data['matches']:
            _id = entry['vulnerability']['id']
            severity = 0
            if len(entry['vulnerability']['cvss']) > 0:
                severity = entry['vulnerability']['cvss'][0]['metrics']['baseScore']
            if severity == 0:
                vul_counts['none'] += 1
            elif 0.1 <= severity <= 3.9:
                vul_counts['low'] += 1
            elif 4.0 <= severity <= 6.9:
                vul_counts['medium'] += 1
            elif 7.0 <= severity <= 8.9:
                vul_counts['high'] += 1
            elif 9.0 <= severity <= 10.0:
                vul_counts['critical'] += 1

            vuls.append(f"{_id}:{severity}")

    return vul_counts, vuls

def process_cve_bin_tool_data(gen_tool, spec, name):
    path = f"02_evaluate/04_product/{gen_tool}/{spec}/cve_bin_tool/cve-bin-tool-results_{name}.json"
    vul_counts = {'total': -1, 'none': -1, 'low': -1, 'medium': -1, 'high': -1, 'critical': -1}

    try:
        with open(path, 'r') as file:
            try:
                data = json.load(file)
            except:
                # print(f"Error opening {path} grype reporting 0 vulnerabilities for this SBOM")
                return vul_counts, -1
    except:
        #print(f"Error opening {path} cve_bin_tool reporting -1 vulnerabilities for this SBOM")
        return vul_counts, -1

    vul_counts = {'total': 0, 'none': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    vuls = []

    for entry in data:
        vul_counts['total'] += 1
        _id = entry['cve_number']
        severity = 0
        if 'score' in entry:
            severity = entry['score']
        if severity == 'unknown':
            vuls.append(f"{_id}:{severity}")
            continue
        else:
            severity = float(severity)
        if severity == 0:
            vul_counts['none'] += 1
        elif 0.1 <= severity <= 3.9:
            vul_counts['low'] += 1
        elif 4.0 <= severity <= 6.9:
            vul_counts['medium'] += 1
        elif 7.0 <= severity <= 8.9:
            vul_counts['high'] += 1
        elif 9.0 <= severity <= 10.0:
            vul_counts['critical'] += 1

        vuls.append(f"{_id}:{severity}")

    return vul_counts, vuls

def process_sbomqs_data(gen_tool, spec, name):
    path = f"02_evaluate/04_product/{gen_tool}/{spec}/sbomqs/sbomqs-results_{name}.json"
    try:
        with open(path, 'r') as file:
            try:
                data = json.load(file)
            except:
                #print(f"Error opening {path} sbomqs reporting 0 packages for this SBOM")
                return -1
    except:
        #print(f"Error opening {path} sbomqs reporting 0 packages for this SBOM")
        return -1

    return data['files'][0]['num_components']


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument("-gt", "--gen_tool", dest="gen_tool", default="", help="")
    parser.add_argument("-s", "--spec", dest="spec", default="", help="")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"
    gen_tool = args.gen_tool
    spec = args.spec

    df = pd.DataFrame(schema)

    print(f"start build data frame for {gen_tool} {spec}...")
    for filename in os.listdir(_input):
        name_without_extension, _ = os.path.splitext(filename)
        trivy_vul_counts, trivy_vuls = process_trivy_data(gen_tool, spec, name_without_extension)
        grype_vul_counts, grype_vuls = process_grype_data(gen_tool, spec, name_without_extension)
        cve_bin_tool_vul_counts, cve_bin_tool_vuls = process_cve_bin_tool_data(gen_tool, spec, name_without_extension)
        package_count = process_sbomqs_data(gen_tool, spec, name_without_extension)
        metadata = name_without_extension.split('_')
        _gen_tool, gen_tool_version = metadata[1].split(':', 1)
        target, target_version = metadata[2].split(':', 1)
        df = df.append({
            'target': target,
            'target_version': target_version,
            'gen_tool': _gen_tool,
            'gen_tool_version': gen_tool_version,
            'spec': spec,
            'num_components': package_count,
            'trivy_total_vuls': trivy_vul_counts['total'],
            'trivy_none_vuls': trivy_vul_counts['none'],
            'trivy_low_vuls': trivy_vul_counts['low'],
            'trivy_medium_vuls': trivy_vul_counts['medium'],
            'trivy_high_vuls': trivy_vul_counts['high'],
            'trivy_critical_vuls': trivy_vul_counts['critical'],
            'trivy_vuls': trivy_vuls,
            'grype_total_vuls': grype_vul_counts['total'],
            'grype_none_vuls': grype_vul_counts['none'],
            'grype_low_vuls': grype_vul_counts['low'],
            'grype_medium_vuls': grype_vul_counts['medium'],
            'grype_high_vuls': grype_vul_counts['high'],
            'grype_critical_vuls': grype_vul_counts['critical'],
            'grype_vuls': grype_vuls,
            'cve_bin_tool_total_vuls': cve_bin_tool_vul_counts['total'],
            'cve_bin_tool_none_vuls': cve_bin_tool_vul_counts['none'],
            'cve_bin_tool_low_vuls': cve_bin_tool_vul_counts['low'],
            'cve_bin_tool_medium_vuls': cve_bin_tool_vul_counts['medium'],
            'cve_bin_tool_high_vuls': cve_bin_tool_vul_counts['high'],
            'cve_bin_tool_critical_vuls': cve_bin_tool_vul_counts['critical'],
            'cve_bin_tool_vuls': cve_bin_tool_vuls
        }, ignore_index=True)

    # print(df['trivy_total_vuls'].value_counts().get(-1, 0))
    # print(df['grype_total_vuls'].value_counts().get(-1, 0))
    # print(df['cve_bin_tool_total_vuls'].value_counts().get(-1, 0))
    output_path = output + f"compiled_results_for_sboms_{gen_tool}_{spec}.csv"
    df.to_csv(output_path, index=False)
    print("finish\n\n")

main()
