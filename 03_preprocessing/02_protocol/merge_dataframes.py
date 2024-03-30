import argparse

import pandas as pd


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    syft_spdx_df = pd.read_csv(_input + "compiled_results_for_sboms_syft_SPDX2.2.csv")
    trivy_spdx_df = pd.read_csv(_input + "compiled_results_for_sboms_trivy_g_SPDX2.2.csv")

    syft_cdx_df = pd.read_csv(_input + "compiled_results_for_sboms_syft_CDX1.5.csv")
    trivy_cdx_df = pd.read_csv(_input + "compiled_results_for_sboms_trivy_g_CDX1.5.csv")

    print("start merging...\n")
    merged_df = pd.merge(trivy_spdx_df, syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    merged_df['name'] = merged_df['target'] + "_" + merged_df['target_version']
    #merged_df = merged_df.loc[(merged_df != -1).all(axis=1)]
    output_path = output + f"merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv"
    merged_df.to_csv(output_path, index=False)

    merged_df = pd.merge(trivy_cdx_df, syft_cdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'),how='inner')
    merged_df['name'] = merged_df['target'] + "_" + merged_df['target_version']
    # merged_df = merged_df.loc[(merged_df != -1).all(axis=1)]
    output_path = output + f"merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv"
    merged_df.to_csv(output_path, index=False)



    merged_df = pd.merge(trivy_spdx_df, trivy_cdx_df, on=['target', 'target_version'], suffixes=(f'_spdx', f'_cdx'), how='inner')
    merged_df['name'] = merged_df['target'] + "_" + merged_df['target_version']
    #merged_df = merged_df.loc[(merged_df != -1).all(axis=1)]
    output_path = output + f"merged_results_for_sboms_trivy_g_spdx_and_cdx.csv"
    merged_df.to_csv(output_path, index=False)

    merged_df = pd.merge(syft_spdx_df, syft_cdx_df, on=['target', 'target_version'], suffixes=(f'_spdx', f'_cdx'), how='inner')
    merged_df['name'] = merged_df['target'] + "_" + merged_df['target_version']
    #merged_df = merged_df.loc[(merged_df != -1).all(axis=1)]
    output_path = output + f"merged_results_for_sboms_syft_spdx_and_cdx.csv"
    merged_df.to_csv(output_path, index=False)
    print("finish\n\n")



    print("start create long format...\n")
    ###################### SPDX #############################
    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['trivy_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['trivy_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_spdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'trivy_total_vuls_trivy_g': 'Trivy_G', 'trivy_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_G', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_spdx_trivy_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['grype_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['grype_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_spdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'grype_total_vuls_trivy_g': 'Trivy_G', 'grype_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_G', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_spdx_grype_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['cve_bin_tool_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['cve_bin_tool_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_spdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'cve_bin_tool_total_vuls_trivy_g': 'Trivy_G', 'cve_bin_tool_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_G', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_spdx_cve_bin_tool_vul_findings.csv"
    long_df.to_csv(output_path, index=False)



    spdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv")
    spdx_merged_df.rename(columns={'num_components_trivy_g': 'Trivy_g', 'num_components_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(spdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool',value_name='findings_count')
    output_path = output + f"long_df_spdx_num_components.csv"
    long_df.to_csv(output_path, index=False)

    spdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv")
    spdx_merged_df.rename(columns={'trivy_total_vuls_trivy_g': 'Trivy_g', 'trivy_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(spdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool',value_name='findings_count')
    output_path = output + f"long_df_spdx_trivy_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    spdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv")
    spdx_merged_df.rename(columns={'grype_total_vuls_trivy_g': 'Trivy_g', 'grype_total_vuls_syft': 'Syft'},inplace=True)
    long_df = pd.melt(spdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool',value_name='findings_count')
    output_path = output + f"long_df_spdx_grype_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    spdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv")
    spdx_merged_df.rename(columns={'cve_bin_tool_total_vuls_trivy_g': 'Trivy_g', 'cve_bin_tool_total_vuls_syft': 'Syft'},inplace=True)
    long_df = pd.melt(spdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool',value_name='findings_count')
    output_path = output + f"long_df_spdx_cve_bin_tool_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    ###################### CDX #############################
    # cdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv")
    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['trivy_total_vuls'] != -1)]
    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['trivy_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _syft_cdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'trivy_total_vuls_trivy_g': 'Trivy_g', 'trivy_total_vuls_syft': 'Syft'},inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_cdx_trivy_vul_findings.csv"
    long_df.to_csv(output_path, index=False)


    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['grype_total_vuls'] != -1)]
    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['grype_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _syft_cdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'grype_total_vuls_trivy_g': 'Trivy_g', 'grype_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_cdx_grype_vul_findings.csv"
    long_df.to_csv(output_path, index=False)


    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['cve_bin_tool_total_vuls'] != -1)]
    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['cve_bin_tool_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _syft_cdx_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'cve_bin_tool_total_vuls_trivy_g': 'Trivy_g', 'cve_bin_tool_total_vuls_syft': 'Syft'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_cdx_cve_bin_tool_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    # cdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv")
    # cdx_merged_df.rename(columns={'num_components_trivy_g': 'Trivy_g', 'num_components_syft': 'Syft'}, inplace=True)
    # long_df = pd.melt(cdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_cdx_num_components.csv"
    # long_df.to_csv(output_path, index=False)
    # cdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv")
    # cdx_merged_df.rename(columns={'grype_total_vuls_trivy_g': 'Trivy_g', 'grype_total_vuls_syft': 'Syft'}, inplace=True)
    # long_df = pd.melt(cdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_cdx_grype_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # cdx_merged_df = pd.read_csv(output + "merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv")
    # cdx_merged_df.rename(columns={'cve_bin_tool_total_vuls_trivy_g': 'Trivy_g', 'cve_bin_tool_total_vuls_syft': 'Syft'}, inplace=True)
    # long_df = pd.melt(cdx_merged_df, id_vars=['name'], value_vars=['Trivy_g', 'Syft'], var_name='gen_tool',value_name='findings_count')
    # output_path = output + f"long_df_cdx_cve_bin_tool_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)

    ###################### Trivy ##############################
    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['trivy_total_vuls'] != -1)]
    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['trivy_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _trivy_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'trivy_total_vuls_cdx': 'CDX 1.5', 'trivy_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_trivy_g_trivy_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['grype_total_vuls'] != -1)]
    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['grype_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _trivy_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'grype_total_vuls_cdx': 'CDX 1.5', 'grype_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_trivy_g_grype_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _trivy_cdx_df = trivy_cdx_df[(trivy_cdx_df['cve_bin_tool_total_vuls'] != -1)]
    _trivy_spdx_df = trivy_spdx_df[(trivy_spdx_df['cve_bin_tool_total_vuls'] != -1)]
    _merged_df = pd.merge(_trivy_cdx_df, _trivy_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'cve_bin_tool_total_vuls_cdx': 'CDX 1.5', 'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_trivy_g_cve_bin_tool_vul_findings.csv"
    long_df.to_csv(output_path, index=False)


    # trivy_g_merged_df = pd.read_csv(output + "merged_results_for_sboms_trivy_g_spdx_and_cdx.csv")
    # trivy_g_merged_df.rename(columns={'num_components_spdx': 'SPDX 2.2', 'num_components_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(trivy_g_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_trivy_g_num_components.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # trivy_g_merged_df = pd.read_csv(output + "merged_results_for_sboms_trivy_g_spdx_and_cdx.csv")
    # trivy_g_merged_df.rename(columns={'trivy_total_vuls_spdx': 'SPDX 2.2', 'trivy_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(trivy_g_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_trivy_g_trivy_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # trivy_g_merged_df = pd.read_csv(output + "merged_results_for_sboms_trivy_g_spdx_and_cdx.csv")
    # trivy_g_merged_df.rename(columns={'grype_total_vuls_spdx': 'SPDX 2.2', 'grype_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(trivy_g_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_trivy_g_grype_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # trivy_g_merged_df = pd.read_csv(output + "merged_results_for_sboms_trivy_g_spdx_and_cdx.csv")
    # trivy_g_merged_df.rename(columns={'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2', 'cve_bin_tool_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(trivy_g_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_trivy_g_cve_bin_tool_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)

    ###################### Syft ##############################
    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['trivy_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['trivy_total_vuls'] != -1)]
    _merged_df = pd.merge(_syft_cdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'trivy_total_vuls_cdx': 'CDX 1.5', 'trivy_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_syft_trivy_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['grype_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['grype_total_vuls'] != -1)]
    _merged_df = pd.merge(_syft_cdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'grype_total_vuls_cdx': 'CDX 1.5', 'grype_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_syft_grype_vul_findings.csv"
    long_df.to_csv(output_path, index=False)

    _syft_cdx_df = syft_cdx_df[(syft_cdx_df['cve_bin_tool_total_vuls'] != -1)]
    _syft_spdx_df = syft_spdx_df[(syft_spdx_df['cve_bin_tool_total_vuls'] != -1)]
    _merged_df = pd.merge(_syft_cdx_df, _syft_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    _merged_df['name'] = _merged_df['target'] + "_" + _merged_df['target_version']
    _merged_df.rename(columns={'cve_bin_tool_total_vuls_cdx': 'CDX 1.5', 'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2'}, inplace=True)
    long_df = pd.melt(_merged_df, id_vars=['name'], value_vars=['CDX 1.5', 'SPDX 2.2'], var_name='gen_tool', value_name='findings_count')
    output_path = output + f"long_df_syft_cve_bin_tool_vul_findings.csv"
    long_df.to_csv(output_path, index=False)


    # syft_merged_df = pd.read_csv(output + "merged_results_for_sboms_syft_spdx_and_cdx.csv")
    # syft_merged_df.rename(columns={'num_components_spdx': 'SPDX 2.2', 'num_components_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(syft_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_syft_num_components.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # syft_merged_df = pd.read_csv(output + "merged_results_for_sboms_syft_spdx_and_cdx.csv")
    # syft_merged_df.rename(columns={'trivy_total_vuls_spdx': 'SPDX 2.2', 'trivy_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(syft_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_syft_trivy_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # syft_merged_df = pd.read_csv(output + "merged_results_for_sboms_syft_spdx_and_cdx.csv")
    # syft_merged_df.rename(columns={'grype_total_vuls_spdx': 'SPDX 2.2', 'grype_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(syft_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_syft_grype_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)
    #
    # syft_merged_df = pd.read_csv(output + "merged_results_for_sboms_syft_spdx_and_cdx.csv")
    # syft_merged_df.rename(columns={'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2', 'cve_bin_tool_total_vuls_cdx': 'CycloneDX 1.5'}, inplace=True)
    # long_df = pd.melt(syft_merged_df, id_vars=['name'], value_vars=['SPDX 2.2', 'CycloneDX 1.5'], var_name='gen_tool', value_name='findings_count')
    # output_path = output + f"long_df_syft_cve_bin_tool_vul_findings.csv"
    # long_df.to_csv(output_path, index=False)

    print("finish\n\n")


main()
