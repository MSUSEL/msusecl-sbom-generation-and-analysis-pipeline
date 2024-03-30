import argparse
import pandas as pd
import os
import matplotlib.pyplot as plt

def build_scatter_plots(df, output, max_packs, max_vuls, gen_tool, spec):
    plt.scatter(df['num_components'], df['trivy_total_vuls'], alpha=0.5)
    plt.xlabel('Package Count', fontsize=13)
    plt.ylabel('Vulnerability Count', fontsize=13)
    plt.grid(True)
    plt.ylim(0, max_vuls + 10)
    plt.xlim(0, max_packs + 10)
    print(f"saving {gen_tool} {spec} trivy_a figure")
    plt.savefig(output + f'pkgs_vs_vuls/sboms-{gen_tool}-{spec}-trivy_a-packages-vs-vuls-scatter.png')
    plt.clf()
    print()
    print()

    plt.scatter(df['num_components'], df['grype_total_vuls'], alpha=0.5)
    plt.xlabel('Package Count', fontsize=13)
    plt.ylabel('Vulnerability Count', fontsize=13)
    plt.grid(True)
    plt.ylim(0, max_vuls + 10)
    plt.xlim(0, max_packs + 10)
    print(f"saving {gen_tool} {spec} trivy_a figure")
    plt.savefig(output + f'pkgs_vs_vuls/sboms-{gen_tool}-{spec}-grype-packages-vs-vuls-scatter.png')
    plt.clf()
    print()
    print()

    return 0
    plt.scatter(df['num_components'], df['cve_bin_tool_total_vuls'], alpha=0.5)
    plt.xlabel('Package Count', fontsize=13)
    plt.ylabel('Vulnerability Count', fontsize=13)
    plt.grid(True)
    plt.ylim(0, max_vuls + 10)
    plt.xlim(0, max_packs + 10)
    print(f"saving {gen_tool} {spec} trivy_a figure")
    plt.savefig(output + f'pkgs_vs_vuls/sboms-{gen_tool}-{spec}-grype-packages-vs-vuls-scatter.png')
    plt.clf()
    print()
    print()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    max_grype_vuls = 0
    max_trivy_vuls = 0
    max_cve_bin_tool_vuls = 0
    max_packs = 0

    for filename in os.listdir(_input):
        if filename.endswith('.csv'):
            df = pd.read_csv(_input + filename)
            max_trivy_vuls = max(max_trivy_vuls, df['trivy_total_vuls'].max())
            max_grype_vuls = max(max_grype_vuls, df['grype_total_vuls'].max())
            max_cve_bin_tool_vuls = max(max_cve_bin_tool_vuls, df['cve_bin_tool_total_vuls'].max())
            max_packs = max(max_packs, df['num_components'].max())
    max_vuls = max(max_trivy_vuls, max_grype_vuls, max_cve_bin_tool_vuls)

    for filename in os.listdir(_input):
        if filename.endswith('.csv'):
            if "syft" in filename and "CDX1.5" in filename:
                df = pd.read_csv(_input + filename)
                df = df[(df['trivy_vuls'] != -1) & (df['grype_vuls'] != -1) & (df['num_components'] != -1)]
                build_scatter_plots(df, output, max_packs, max_vuls, "syft", "CDX1.5")
            if "syft" in filename and "SPDX2.2" in filename:
                df = pd.read_csv(_input + filename)
                df = df[(df['trivy_vuls'] != -1) & (df['grype_vuls'] != -1) & (df['num_components'] != -1)]
                build_scatter_plots(df, output, max_packs, max_vuls, "syft", "SPDX2.2")
            if "trivy_g" in filename and "CDX1.5" in filename:
                df = pd.read_csv(_input + filename)
                df = df[(df['trivy_vuls'] != -1) & (df['grype_vuls'] != -1) & (df['num_components'] != -1)]
                build_scatter_plots(df, output, max_packs, max_vuls, "trivy_g", "CDX1.5")
            if "trivy_g" in filename and "SPDX2.2" in filename:
                df = pd.read_csv(_input + filename)
                df = df[(df['trivy_vuls'] != -1) & (df['grype_vuls'] != -1) & (df['num_components'] != -1)]
                build_scatter_plots(df, output, max_packs, max_vuls, "trivy_g", "SPDX2.2")


main()
