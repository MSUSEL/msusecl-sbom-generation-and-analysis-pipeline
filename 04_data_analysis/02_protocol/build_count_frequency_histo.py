import argparse
import pandas as pd
import os
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np



def build_histogram(df, output, max_vuls, gen_tool, spec, severity):
    df = df[(df[f'trivy_{severity}_vuls'] != -1) & (df[f'grype_{severity}_vuls'] != -1) & (df['num_components'] != -1)]

    plt.figure(figsize=(10, 6))
    plt.hist(df[f'num_components'], bins=100, color='gray', edgecolor='black', alpha=0.7)
    plt.xlabel('Package Count')
    plt.ylabel('Frequency')
    #plt.xlim(0, max_vuls + 10)
    print(f"saving SBOMs {gen_tool} -- num_components vul figure")
    plt.savefig(output + f'histograms/sbom_{gen_tool}_{spec}_vuls_{severity}_num_components.png')
    plt.clf()
    print()
    print()


    plt.figure(figsize=(10, 6))
    plt.hist(df[f'trivy_{severity}_vuls'], bins=100, color='skyblue', edgecolor='black', alpha=0.7)
    plt.xlabel('Vulnerability Count')
    plt.ylabel('Frequency')
    plt.xlim(0, max_vuls + 10)
    print(f"saving SBOMs {gen_tool} -- trivy vul figure")
    plt.savefig(output + f'histograms/sbom_{gen_tool}_{spec}_vuls_{severity}_trivy.png')
    plt.clf()
    print()
    print()


    plt.figure(figsize=(10, 6))
    plt.hist(df[f'grype_{severity}_vuls'], bins=100, color='orange', edgecolor='black', alpha=0.7)
    plt.xlabel('Vulnerability Count')
    plt.ylabel('Frequency')
    plt.xlim(0, max_vuls + 10)
    print(f"saving SBOMs {gen_tool} -- grype vul figure")
    plt.savefig(output + f'histograms/sbom_{gen_tool}_{spec}_vuls_{severity}_grype.png')
    plt.clf()
    print()
    print()


    plt.figure(figsize=(10, 6))
    plt.hist(df[f'cve_bin_tool_{severity}_vuls'], bins=100, color='red', edgecolor='black', alpha=0.7)
    plt.xlabel('Vulnerability Count')
    plt.ylabel('Frequency')
    plt.xlim(0, max_vuls + 10)
    print(f"saving SBOMs {gen_tool} -- cve_bin_tool vul figure")
    plt.savefig(output + f'histograms/sbom_{gen_tool}_{spec}_vuls_{severity}_cve_bin_tool.png')
    plt.clf()
    print()
    print()

def build_violin_gen_tool(t_df, s_df, output, spec):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        t_df[column] = np.where(t_df[column] == -1, np.nan, t_df[column])
    for column in columns_to_check:
        s_df[column] = np.where(s_df[column] == -1, np.nan, s_df[column])
    merged_df = pd.merge(t_df, s_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')

    columns_and_labels = {
        'trivy_total_vuls_syft': 'Syft',
        'trivy_total_vuls_trivy_g': 'Trivy_G',
        'grype_total_vuls_syft': 'Syft',
        'grype_total_vuls_trivy_g': 'Trivy_G',
        'cve_bin_tool_total_vuls_syft': 'Syft',
        'cve_bin_tool_total_vuls_trivy_g': 'Trivy_G',
    }
    columns_and_colors = {
        'trivy_total_vuls_syft': '#6495ed',
        'trivy_total_vuls_trivy_g': '#ff717f',
        'grype_total_vuls_syft': '#6495ed',
        'grype_total_vuls_trivy_g': '#ff717f',
        'cve_bin_tool_total_vuls_syft': '#6495ed',
        'cve_bin_tool_total_vuls_trivy_g': '#ff717f',
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile", cut=0)
    plt.xlabel('Generation Tool & Specification', fontsize=18)
    plt.ylabel(r'Findings', fontsize=18)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='cornflowerblue', lw=4, label='Syft'),
        plt.Line2D([0], [0], color='orange', lw=4, label='Trivy_G')
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins/figure2-{spec}.png')
    plt.clf()
    print()
    print()


    # columns_and_labels = {
    #     'num_components_syft': 'Syft',
    #     'num_components_trivy_g': 'Trivy'
    # }
    # columns_and_colors = {
    #     'num_components_syft': 'cornflowerblue',
    #     'num_components_trivy_g': 'orange'
    # }
    #
    # plt.figure(figsize=(12, 8))
    # plot_data = merged_df[list(columns_and_labels.keys())]
    # melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    # melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)
    #
    # sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    # plt.xlabel('SBOM Generation Tool', fontsize=18)
    # plt.ylabel(r'# Components', fontsize=18)
    #
    # custom_legend = [
    #     plt.Line2D([0], [0], color='cornflowerblue', lw=4, label='Syft'),
    #     plt.Line2D([0], [0], color='orange', lw=4, label='Trivy_G')
    # ]
    # plt.legend(handles=custom_legend, loc='upper right')
    #
    # print(f"saving SBOM all gen,num_comps combos violins")
    # plt.savefig(output + f'violins/sbom_{spec}--trivy_g-num_comps__syft-num_comps.png')
    # plt.clf()
    # print()
    # print()

def build_violin_spec(spdx_df, cdx_df, output, gen_tool, severity):
    spdx_df = spdx_df[(spdx_df[f'trivy_{severity}_vuls'] != -1) & (spdx_df[f'grype_{severity}_vuls'] != -1) & (spdx_df['num_components'] != -1) & (spdx_df['cve_bin_tool_total_vuls'] != -1)]
    cdx_df = cdx_df[(cdx_df[f'trivy_{severity}_vuls'] != -1) & (cdx_df[f'grype_{severity}_vuls'] != -1) & (cdx_df['num_components'] != -1) & (cdx_df['cve_bin_tool_total_vuls'] != -1)]
    merged_df = pd.merge(spdx_df, cdx_df, on=['target', 'target_version'], suffixes=(f'_spdx', f'_cdx'), how='inner')

    columns_and_labels = {
        'trivy_total_vuls_cdx': 'Trivy ',
        'trivy_total_vuls_spdx': 'Trivy',
        'grype_total_vuls_cdx': 'Grype ',
        'grype_total_vuls_spdx': 'Grype',
        'cve_bin_tool_total_vuls_cdx': 'CVE-bin-tool ',
        'cve_bin_tool_total_vuls_spdx': 'CVE-bin-tool'
    }
    columns_and_colors = {
        'trivy_total_vuls_cdx': 'coral',
        'trivy_total_vuls_spdx': 'plum',
        'grype_total_vuls_cdx': 'coral',
        'grype_total_vuls_spdx': 'plum',
        'cve_bin_tool_total_vuls_cdx': 'coral',
        'cve_bin_tool_total_vuls_spdx': 'plum'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('Analysis Tool', fontsize=18)
    plt.ylabel(r'Findings', fontsize=18)

    custom_legend = [
        plt.Line2D([0], [0], color='coral', lw=4, label='CycloneDX 1.5'),
        plt.Line2D([0], [0], color='plum', lw=4, label='SPDX 2.2')
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all spec,analysis combos violins")
    plt.savefig(output + f'violins/sbom_{gen_tool}--spdx-trivy__cdx-trivy__spdx-grype__cdx-grype__cve-bin-tool.png')
    plt.clf()
    print()
    print()


    columns_and_labels = {
        'num_components_cdx': 'CDX',
        'num_components_spdx': 'SPDX'
    }
    columns_and_colors = {
        'num_components_cdx': 'coral',
        'num_components_spdx': 'plum'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('SBOM Generation tool used', fontsize=18)
    plt.ylabel(r'# Components', fontsize=18)

    custom_legend = [
        plt.Line2D([0], [0], color='coral', lw=4, label='CycloneDX 1.5'),
        plt.Line2D([0], [0], color='plum', lw=4, label='SPDX 2.2')
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    print(f"saving SBOM all spec,num_comps combos violins")
    plt.savefig(output + f'violins/sbom_{gen_tool}--spdx-num_comps__cdx-num_comps.png')
    plt.clf()
    print()
    print()

def build_comparison_histograms(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'trivy_{severity}_vuls'] != -1) & (df1[f'grype_{severity}_vuls'] != -1) & (df1['num_components'] != -1)]
    df2 = df2[(df2[f'trivy_{severity}_vuls'] != -1) & (df2[f'grype_{severity}_vuls'] != -1) & (df2['num_components'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Create a histogram
    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'trivy_{severity}_vuls_diff'], bins=100, color='orange', alpha=0.7, label='Trivy Vuls Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Trivy Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure")
    plt.savefig(output + f'difference_histos/sbom_{constant}--{df1_type}-versus-{df2_type}_{severity}_vuls_trivy.png')
    plt.clf()
    print()
    print()

    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'grype_{severity}_vuls_diff'], bins=100, color='blue', alpha=0.7, label='Grype Vuls Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Grype Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure")
    plt.savefig(output + f'difference_histos/sbom_{constant}--{df1_type}-versus-{df2_type}_{severity}_vuls_grype.png')
    plt.clf()
    print()
    print()

def build_comparison_num_comps_histograms(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'trivy_{severity}_vuls'] != -1) & (df1[f'grype_{severity}_vuls'] != -1) & (df1['num_components'] != -1)]
    df2 = df2[(df2[f'trivy_{severity}_vuls'] != -1) & (df2[f'grype_{severity}_vuls'] != -1) & (df2['num_components'] != -1)]

    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')
    merged_df[f'num_components_diff'] = merged_df[f'num_components_{df1_type}'] - merged_df[f'num_components_{df2_type}']
    merged_df.to_csv(output + f"merged_comp_diff_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Create a histogram
    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'num_components_diff'], bins=100, color='orange', alpha=0.7, label='Trivy Components Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Trivy Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} number components figure")
    plt.savefig(output + f'difference_histos/sbom_{constant}--{df1_type}-versus-{df2_type}_num_components.png')
    plt.clf()
    print()
    print()


def build_comparison_violins_total(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'trivy_{severity}_vuls'] != -1) & (df1[f'grype_{severity}_vuls'] != -1) & (df1['num_components'] != -1)]
    df2 = df2[(df2[f'trivy_{severity}_vuls'] != -1) & (df2[f'grype_{severity}_vuls'] != -1) & (df2['num_components'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    columns_and_colors = {
        f'trivy_total_vuls_diff': 'orange'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_colors.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('Trivy Vulnerability Findings', fontsize=13)
    plt.ylabel(r'$\Delta$ Findings', fontsize=13)
    plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Findings Difference')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure with side-by-side violin plots")
    plt.savefig(output + f'violins_comp/sbom_{constant}--{df1_type}-versus-{df2_type}_single_violin_trivy_vul_results.png')
    plt.clf()
    print()
    print()

    columns_and_colors = {
        f'grype_total_vuls_diff': 'cornflowerblue'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_colors.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('Grype Vulnerability Findings', fontsize=13)
    plt.ylabel(r'$\Delta$ Findings', fontsize=13)
    plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Findings Difference')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure with side-by-side violin plots")
    plt.savefig(output + f'violins_comp/sbom_{constant}--{df1_type}-versus-{df2_type}_single_violin_grype_vul_results.png')
    plt.clf()
    print()
    print()

    
    columns_and_colors = {
        f'trivy_total_vuls_diff': 'orange',
        f'grype_total_vuls_diff': 'cornflowerblue'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_colors.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('SBOM Analysis Tool', fontsize=13)
    plt.ylabel(r'$\Delta$ Findings', fontsize=13)
    plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Findings Difference')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure with trivy and grype totals violin plots")
    plt.savefig(output + f'violins_comp/sbom_{constant}--{df1_type}-versus-{df2_type}_double_violin_trivy_gyrpe_total_vul_results.png')
    plt.clf()
    print()
    print()


def build_comparison_violins_severity(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'trivy_{severity}_vuls'] != -1) & (df1[f'grype_{severity}_vuls'] != -1) & (df1['num_components'] != -1)]
    df2 = df2[(df2[f'trivy_{severity}_vuls'] != -1) & (df2[f'grype_{severity}_vuls'] != -1) & (df2['num_components'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Specify the columns and colors for the violin plots
    # f'trivy_total_vuls_diff': 'gray',
    columns_and_colors = {
        f'trivy_none_vuls_diff': 'lightgray',
        f'trivy_low_vuls_diff': 'green',
        f'trivy_medium_vuls_diff': 'yellow',
        f'trivy_high_vuls_diff': 'orange',
        f'trivy_critical_vuls_diff': 'red',
    }
    merged_df[f'trivy_none_vuls_diff'] = merged_df[f'trivy_none_vuls_{df1_type}'] - merged_df[f'trivy_none_vuls_{df2_type}']
    merged_df[f'grype_none_vuls_diff'] = merged_df[f'grype_none_vuls_{df1_type}'] - merged_df[f'grype_none_vuls_{df2_type}']
    merged_df[f'trivy_low_vuls_diff'] = merged_df[f'trivy_low_vuls_{df1_type}'] - merged_df[f'trivy_low_vuls_{df2_type}']
    merged_df[f'grype_low_vuls_diff'] = merged_df[f'grype_low_vuls_{df1_type}'] - merged_df[f'grype_low_vuls_{df2_type}']
    merged_df[f'trivy_medium_vuls_diff'] = merged_df[f'trivy_medium_vuls_{df1_type}'] - merged_df[f'trivy_medium_vuls_{df2_type}']
    merged_df[f'grype_medium_vuls_diff'] = merged_df[f'grype_medium_vuls_{df1_type}'] - merged_df[f'grype_medium_vuls_{df2_type}']
    merged_df[f'trivy_high_vuls_diff'] = merged_df[f'trivy_high_vuls_{df1_type}'] - merged_df[f'trivy_high_vuls_{df2_type}']
    merged_df[f'grype_high_vuls_diff'] = merged_df[f'grype_high_vuls_{df1_type}'] - merged_df[f'grype_high_vuls_{df2_type}']
    merged_df[f'trivy_critical_vuls_diff'] = merged_df[f'trivy_critical_vuls_{df1_type}'] - merged_df[f'trivy_critical_vuls_{df2_type}']
    merged_df[f'grype_critical_vuls_diff'] = merged_df[f'grype_critical_vuls_{df1_type}'] - merged_df[f'grype_critical_vuls_{df2_type}']


    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_colors.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    positions = range(len(columns_and_colors))
    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('Severity Level', fontsize=13)
    plt.ylabel(r'$\Delta$ Findings', fontsize=13)
    plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Findings Difference')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure with side-by-side violin plots")
    plt.savefig(output + f'violins_comp/severity/sbom_{constant}--{df1_type}-versus-{df2_type}_severity_side_by_side_violin_trivy_vul_results.png')
    plt.clf()
    print()
    print()

    # f'grype_total_vuls_diff': 'gray',
    columns_and_colors = {
        f'grype_none_vuls_diff': 'lightgray',
        f'grype_low_vuls_diff': 'green',
        f'grype_medium_vuls_diff': 'yellow',
        f'grype_high_vuls_diff': 'orange',
        f'grype_critical_vuls_diff': 'red'
    }
    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_colors.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    positions = range(len(columns_and_colors))
    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
    plt.xlabel('Severity Level', fontsize=13)
    plt.ylabel(r'$\Delta$ Findings', fontsize=13)
    plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Findings Difference')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure with side-by-side violin plots")
    plt.savefig(output + f'violins_comp/severity/sbom_{constant}--{df1_type}-versus-{df2_type}_severity_side_by_side_violin_grype_vul_results.png')
    plt.clf()
    print()
    print()

def build_cve_bin_tool_comp_histos(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'cve_bin_tool_{severity}_vuls'] != -1)]
    df2 = df2[(df2[f'cve_bin_tool_{severity}_vuls'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'cve_bin_tool_{severity}_vuls_diff'] = merged_df[f'cve_bin_tool_{severity}_vuls_{df1_type}'] - merged_df[f'cve_bin_tool_{severity}_vuls_{df2_type}']
    merged_df[f'cve_bin_tool_{severity}_vuls_diff'] = merged_df[f'cve_bin_tool_{severity}_vuls_{df1_type}'] - merged_df[f'cve_bin_tool_{severity}_vuls_{df2_type}']
    #merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Create a histogram
    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'cve_bin_tool_{severity}_vuls_diff'], bins=100, color='orange', alpha=0.7, label='CVE-bin-tool Vuls Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Trivy Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure")
    plt.savefig(output + f'difference_histos/temp/sbom_{constant}--{df1_type}-versus-{df2_type}_{severity}_vuls_cve_bin_tool.png')
    plt.clf()
    print()
    print()

def build_trivy_g_comp_histos(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'trivy_{severity}_vuls'] != -1)]
    df2 = df2[(df2[f'trivy_{severity}_vuls'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    #merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Create a histogram
    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'trivy_{severity}_vuls_diff'], bins=100, color='orange', alpha=0.7, label='CVE-bin-tool Vuls Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Trivy Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure")
    plt.savefig(output + f'difference_histos/temp/sbom_{constant}--{df1_type}-versus-{df2_type}_{severity}_vuls_trivy_g.png')
    plt.clf()
    print()
    print()

def build_grype_comp_histos(df1, df2, output, df1_type, df2_type, constant, severity):
    df1 = df1[(df1[f'grype_{severity}_vuls'] != -1)]
    df2 = df2[(df2[f'grype_{severity}_vuls'] != -1)]
    merged_df = pd.merge(df1, df2, on=['target', 'target_version'], suffixes=(f'_{df1_type}', f'_{df2_type}'), how='inner')

    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    #merged_df.to_csv(output + f"merged_results_{constant}_{df1_type}-versus-{df2_type}.csv", index=False)

    # Create a histogram
    #plt.figure(figsize=(20, 12))
    plt.hist(merged_df[f'grype_{severity}_vuls_diff'], bins=100, color='orange', alpha=0.7, label='CVE-bin-tool Vuls Diff')
    plt.xlabel('Difference', fontsize=13)
    plt.ylabel('Frequency', fontsize=13)
    plt.grid(False)
    #plt.title(f'SBOMs {constant} -- {df1_type} versus {df2_type} Trivy Vulnerability Count')
    print(f"saving SBOM {constant} -- {df1_type} versus {df2_type} figure")
    plt.savefig(output + f'difference_histos/temp/sbom_{constant}--{df1_type}-versus-{df2_type}_{severity}_vuls_grype.png')
    plt.clf()
    print()
    print()

def build_violin_comp_gen_tool(t_df, s_df, output, spec, severity, df1_type, df2_type):
    t_df = t_df[(t_df[f'trivy_{severity}_vuls'] != -1) & (t_df[f'grype_{severity}_vuls'] != -1) & (t_df['cve_bin_tool_total_vuls'] != -1)]
    s_df = s_df[(s_df[f'trivy_{severity}_vuls'] != -1) & (s_df[f'grype_{severity}_vuls'] != -1) & (s_df['cve_bin_tool_total_vuls'] != -1)]
    merged_df = pd.merge(t_df, s_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')

    merged_df[f'trivy_{severity}_vuls_diff'] = merged_df[f'trivy_{severity}_vuls_{df1_type}'] - merged_df[f'trivy_{severity}_vuls_{df2_type}']
    merged_df[f'grype_{severity}_vuls_diff'] = merged_df[f'grype_{severity}_vuls_{df1_type}'] - merged_df[f'grype_{severity}_vuls_{df2_type}']
    merged_df[f'cve_bin_tool_{severity}_vuls_diff'] = merged_df[f'cve_bin_tool_{severity}_vuls_{df1_type}'] - merged_df[f'cve_bin_tool_{severity}_vuls_{df2_type}']


    columns_and_labels = {
        'trivy_total_vuls_diff': 'Trivy ',
        'grype_total_vuls_diff': 'Grype ',
        'cve_bin_tool_total_vuls_diff': 'CVE-bin-tool '
    }
    columns_and_colors = {
        'trivy_total_vuls_diff': 'darkorange',
        'grype_total_vuls_diff': 'slateblue',
        'cve_bin_tool_total_vuls_diff': 'tomato'
    }

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile", cut=0)
    plt.xlabel('Analysis Tool', fontsize=18)
    plt.ylabel(r'Findings', fontsize=18)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='darkorange', lw=4, label='Trivy_A'),
        plt.Line2D([0], [0], color='slateblue', lw=4, label='Syft'),
        plt.Line2D([0], [0], color='tomato', lw=4, label='CVE-bin-tool')
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    # Adding semi-transparent lines between specific violins
    # plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    # plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins_comp/violin_comp_sbom_{spec}--trivy_g-trivy__syft-trivy__trivy_g-grype__syft-grype__cve-bin-tool.png')
    plt.clf()
    print()
    print()


def build_figure1(t_cdx_df, s_cdx_df, t_spdx_df, s_spdx_df, output):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        t_cdx_df[column] = np.where(t_cdx_df[column] == -1, np.nan, t_cdx_df[column])
    for column in columns_to_check:
        s_cdx_df[column] = np.where(s_cdx_df[column] == -1, np.nan, s_cdx_df[column])
    for column in columns_to_check:
        t_spdx_df[column] = np.where(t_spdx_df[column] == -1, np.nan, t_spdx_df[column])
    for column in columns_to_check:
        s_spdx_df[column] = np.where(s_spdx_df[column] == -1, np.nan, s_spdx_df[column])

    trivy_spec_merged_df = pd.merge(t_cdx_df, t_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    syft_spec_merged_df = pd.merge(s_cdx_df, s_spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')

    merged_df = pd.merge(trivy_spec_merged_df, syft_spec_merged_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')


    columns_and_labels = {
        'trivy_total_vuls_cdx_syft': ' Syft - CDX',
        'trivy_total_vuls_spdx_syft': ' Syft - SPDX',
        'trivy_total_vuls_cdx_trivy_g': ' Trivy_G - CDX',
        'trivy_total_vuls_spdx_trivy_g': ' Trivy_G - SPDX',
        'grype_total_vuls_cdx_syft': 'Syft - CDX',
        'grype_total_vuls_spdx_syft': 'Syft - SPDX',
        'grype_total_vuls_cdx_trivy_g': 'Trivy_G - CDX',
        'grype_total_vuls_spdx_trivy_g': 'Trivy_G - SPDX',
        'cve_bin_tool_total_vuls_cdx_syft': 'Syft - CDX ',
        'cve_bin_tool_total_vuls_spdx_syft': 'Syft - SPDX ',
        'cve_bin_tool_total_vuls_cdx_trivy_g': 'Trivy_G - CDX ',
        'cve_bin_tool_total_vuls_spdx_trivy_g': 'Trivy_G - SPDX '
    }
    columns_and_colors = {
        'trivy_total_vuls_cdx_syft': '#6495ed',
        'trivy_total_vuls_spdx_syft': '#e67bd6',
        'trivy_total_vuls_cdx_trivy_g': '#ff717f',
        'trivy_total_vuls_spdx_trivy_g': '#ffa600',
        'grype_total_vuls_cdx_syft': '#6495ed',
        'grype_total_vuls_spdx_syft': '#e67bd6',
        'grype_total_vuls_cdx_trivy_g': '#ff717f',
        'grype_total_vuls_spdx_trivy_g': '#ffa600',
        'cve_bin_tool_total_vuls_cdx_syft': '#6495ed',
        'cve_bin_tool_total_vuls_spdx_syft': '#e67bd6',
        'cve_bin_tool_total_vuls_cdx_trivy_g': '#ff717f',
        'cve_bin_tool_total_vuls_spdx_trivy_g': '#ffa600'
    }

    plt.figure(figsize=(12, 8))

    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile", cut=0, dropna=True, linewidth=2)
    plt.xlabel('Analysis Tool', fontsize=18)
    plt.ylabel(r'Findings', fontsize=18)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='#6495ed', lw=4, label='Syft - CDX'),
        plt.Line2D([0], [0], color='#e67bd6', lw=4, label='Syft - SPDX'),
        plt.Line2D([0], [0], color='#ff717f', lw=4, label='Trivy_G - CDX'),
        plt.Line2D([0], [0], color='#ffa600', lw=4, label='Trivy_G - SPDX'),
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    # Adding semi-transparent lines between specific violins
    #plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    #plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    sns.despine()
    plt.gca().set_facecolor('#F5F5F5')
    plt.tick_params(axis='both', which='both', length=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    print(f"saving SBOM all gen,spec,analysis combos violins")
    plt.savefig(output + f'violins/figure1.png')
    plt.clf()
    print()
    print()


def build_figure2_1(t_df, s_df, output, spec, d1, d2):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        t_df[column] = np.where(t_df[column] == -1, np.nan, t_df[column])
    for column in columns_to_check:
        s_df[column] = np.where(s_df[column] == -1, np.nan, s_df[column])
    merged_df = pd.merge(t_df, s_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')

    # get average difference of t_df and d1 on row 'trivy_total_vuls'
    print("###############################################################################################")
    diff = t_df['trivy_total_vuls'] - d1['trivy_total_vuls']
    print(f"trivy_total_vuls - trivy_total_vuls: {diff.mean()}")
    diff = t_df['grype_total_vuls'] - d1['grype_total_vuls']
    print(f"grype_total_vuls - grype_total_vuls: {diff.mean()}")
    diff = t_df['cve_bin_tool_total_vuls'] - d1['cve_bin_tool_total_vuls']
    print(f"cve_bin_tool_total_vuls - cve_bin_tool_total_vuls: {diff.mean()}")

    # get average difference of s_df and d2 on row 'trivy_total_vuls'
    diff = s_df['trivy_total_vuls'] - d2['trivy_total_vuls']
    print(f"trivy_total_vuls - trivy_total_vuls: {diff.mean()}")
    diff = s_df['grype_total_vuls'] - d2['grype_total_vuls']
    print(f"grype_total_vuls - grype_total_vuls: {diff.mean()}")
    diff = s_df['cve_bin_tool_total_vuls'] - d2['cve_bin_tool_total_vuls']
    print(f"cve_bin_tool_total_vuls - cve_bin_tool_total_vuls: {diff.mean()}")
    print("###############################################################################################")
    print("\n\n\n\n")
    columns_and_labels = {
        'trivy_total_vuls_syft': 'Syft',
        'trivy_total_vuls_trivy_g': 'Trivy_G',
        'grype_total_vuls_syft': ' Syft',
        'grype_total_vuls_trivy_g': ' Trivy_G',
        'cve_bin_tool_total_vuls_syft': 'Syft ',
        'cve_bin_tool_total_vuls_trivy_g': 'Trivy_G ',
    }
    columns_and_colors = {
        'trivy_total_vuls_syft': '#6495ed',
        'trivy_total_vuls_trivy_g': '#ff717f',
        'grype_total_vuls_syft': '#6495ed',
        'grype_total_vuls_trivy_g': '#ff717f',
        'cve_bin_tool_total_vuls_syft': '#6495ed',
        'cve_bin_tool_total_vuls_trivy_g': '#ff717f',
    }

    trivy_df = merged_df[['target', 'target_version', 'trivy_total_vuls_trivy_g', 'trivy_total_vuls_syft']]
    grype_df = merged_df[['target', 'target_version', 'grype_total_vuls_trivy_g', 'grype_total_vuls_syft']]
    cve_bin_tool_df = merged_df[['target', 'target_version', 'cve_bin_tool_total_vuls_trivy_g', 'cve_bin_tool_total_vuls_syft']]
    missing_indices = trivy_df.index[(trivy_df['trivy_total_vuls_trivy_g'] == -1) | (trivy_df['trivy_total_vuls_syft'] == -1)]
    trivy_df = trivy_df.drop(missing_indices)
    missing_indices = grype_df.index[(grype_df['grype_total_vuls_trivy_g'] == -1) | (grype_df['grype_total_vuls_syft'] == -1)]
    grype_df = grype_df.drop(missing_indices)
    missing_indices = cve_bin_tool_df.index[(cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] == -1) | (cve_bin_tool_df['cve_bin_tool_total_vuls_syft'] == -1)]
    cve_bin_tool_df = cve_bin_tool_df.drop(missing_indices)


    print("################ CDX Syft versus Trivy_g ################")
    print("-----N------")
    print(f"trivy: {trivy_df['trivy_total_vuls_trivy_g'].count()}")
    print(f"grype: {grype_df['grype_total_vuls_trivy_g'].count()}")
    print(f"cve-bin-tool: {cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'].count()}")


    max_index = grype_df['grype_total_vuls_syft'].idxmax()
    print(f"max index: {max_index}")
    print(f"target: {grype_df['target'][max_index]} {grype_df['target_version'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_syft'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_syft'][max_index]}")

    print("-----average differences------")
    diff = grype_df['grype_total_vuls_syft'] - trivy_df['trivy_total_vuls_syft']
    print(f"syft - grype : syft - trivy {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - grype_df['grype_total_vuls_trivy_g']
    print(f"syft - grype : trivy_g - grype {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"syft - grype : syft - cve-bin-tool {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g']
    print(f"syft - grype : trivy_g - cve-bin-tool {diff.mean()}")

    diff = trivy_df['trivy_total_vuls_trivy_g'] - grype_df['grype_total_vuls_trivy_g']
    print(f"trivy_g - trivy : trivy_g - grype {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_g - trivy : syft - trivy {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g']
    print(f"trivy_g - trivy : trivy_g - cve-bin-tool {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"trivy_g - trivy : syft - cve-bin-tool {diff.mean()}")
    print()
    print()

    print("-----% sboms with same findings------")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_a - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    diff = grype_df['grype_total_vuls_trivy_g'] - grype_df['grype_total_vuls_syft']
    print(f"grype - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"cve-bin-tool - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    print()
    print()

    print("------differences in medians------")
    print(f"trivy_a -> median trivy_g - median syft : {trivy_df['trivy_total_vuls_trivy_g'].median() - trivy_df['trivy_total_vuls_syft'].median()}")
    print(f"grype -> median trivy_g - median syft : {grype_df['grype_total_vuls_trivy_g'].median() - grype_df['grype_total_vuls_syft'].median()}")
    print(f"cve-bin-tool -> median trivy_g - median syft : {cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'].median() - cve_bin_tool_df['cve_bin_tool_total_vuls_syft'].median()}")
    print()
    print()

    print("------range of differences------")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_a -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"trivy_a -> trivy_g - syft std dev: {diff.std()}")

    diff = grype_df['grype_total_vuls_syft'] - grype_df['grype_total_vuls_trivy_g']
    print(f"grype -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"grype -> trivy_g - syft std dev: {diff.std()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"cve-bin-tool -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"cve-bin-tool -> trivy_g - syft std dev: {diff.std()}")
    print()
    print()
    print("\n\n")


    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner=None, cut=0, dropna=True, linewidth=0.5)
    plt.xlabel('Generation Tool', fontsize=22)
    plt.ylabel(r'Findings', fontsize=22)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=14)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='#6495ed', lw=4, label='Syft - CDX 1.5'),
        plt.Line2D([0], [0], color='#ff717f', lw=4, label='Trivy_G - CDX 1.5')
    ]
    plt.legend(handles=custom_legend, loc='upper right', fontsize=16)

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    sns.despine()
    plt.gca().set_facecolor('#F5F5F5')
    plt.tick_params(axis='both', which='both', length=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins/figure2-{spec}.png')
    plt.clf()
    print()
    print()

def build_figure2_2(t_df, s_df, output, spec):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        t_df[column] = np.where(t_df[column] == -1, np.nan, t_df[column])
    for column in columns_to_check:
        s_df[column] = np.where(s_df[column] == -1, np.nan, s_df[column])
    merged_df = pd.merge(t_df, s_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')

    columns_and_labels = {
        'trivy_total_vuls_syft': 'Syft',
        'trivy_total_vuls_trivy_g': 'Trivy_G',
        'grype_total_vuls_syft': ' Syft',
        'grype_total_vuls_trivy_g': ' Trivy_G',
        'cve_bin_tool_total_vuls_syft': 'Syft ',
        'cve_bin_tool_total_vuls_trivy_g': 'Trivy_G ',
    }
    columns_and_colors = {
        'trivy_total_vuls_syft': '#e67bd6',
        'trivy_total_vuls_trivy_g': '#ffa600',
        'grype_total_vuls_syft': '#e67bd6',
        'grype_total_vuls_trivy_g': '#ffa600',
        'cve_bin_tool_total_vuls_syft': '#e67bd6',
        'cve_bin_tool_total_vuls_trivy_g': '#ffa600',
    }

    trivy_df = merged_df[['target', 'target_version', 'trivy_total_vuls_trivy_g', 'trivy_total_vuls_syft']]
    grype_df = merged_df[['target', 'target_version', 'grype_total_vuls_trivy_g', 'grype_total_vuls_syft']]
    cve_bin_tool_df = merged_df[['target', 'target_version', 'cve_bin_tool_total_vuls_trivy_g', 'cve_bin_tool_total_vuls_syft']]
    missing_indices = trivy_df.index[(trivy_df['trivy_total_vuls_trivy_g'] == -1) | (trivy_df['trivy_total_vuls_syft'] == -1)]
    trivy_df = trivy_df.drop(missing_indices)
    missing_indices = grype_df.index[(grype_df['grype_total_vuls_trivy_g'] == -1) | (grype_df['grype_total_vuls_syft'] == -1)]
    grype_df = grype_df.drop(missing_indices)
    missing_indices = cve_bin_tool_df.index[(cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] == -1) | (cve_bin_tool_df['cve_bin_tool_total_vuls_syft'] == -1)]
    cve_bin_tool_df = cve_bin_tool_df.drop(missing_indices)

    print("################ SPDX Syft versus Trivy_g ################")
    print("-----N------")
    print(f"trivy: {trivy_df['trivy_total_vuls_trivy_g'].count()}")
    print(f"grype: {grype_df['grype_total_vuls_trivy_g'].count()}")
    print(f"cve-bin-tool: {cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'].count()}")

    max_index = grype_df['grype_total_vuls_syft'].idxmax()
    print(f"max index: {max_index}")
    print(f"target: {grype_df['target'][max_index]} {grype_df['target_version'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_syft'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_syft'][max_index]}")

    print("-----average differences------")
    diff = grype_df['grype_total_vuls_syft'] - trivy_df['trivy_total_vuls_syft']
    print(f"syft - grype : syft - trivy {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - grype_df['grype_total_vuls_trivy_g']
    print(f"syft - grype : trivy_g - grype {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"syft - grype : syft - cve-bin-tool {diff.mean()}")
    diff = grype_df['grype_total_vuls_syft'] - cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g']
    print(f"syft - grype : trivy_g - cve-bin-tool {diff.mean()}")

    diff = trivy_df['trivy_total_vuls_trivy_g'] - grype_df['grype_total_vuls_trivy_g']
    print(f"trivy_g - trivy : trivy_g - grype {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_g - trivy : syft - trivy {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g']
    print(f"trivy_g - trivy : trivy_g - cve-bin-tool {diff.mean()}")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"trivy_g - trivy : syft - cve-bin-tool {diff.mean()}")
    print()
    print()

    print("-----% sboms with same findings------")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_a - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    diff = grype_df['grype_total_vuls_trivy_g'] - grype_df['grype_total_vuls_syft']
    print(f"grype - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"cve-bin-tool - % same trivy_g -> syft : {diff[diff == 0].count() / diff.count()}")
    print()
    print()

    print("------differences in medians------")
    print(f"trivy_a -> median trivy_g - median syft : {trivy_df['trivy_total_vuls_trivy_g'].median() - trivy_df['trivy_total_vuls_syft'].median()}")
    print(f"grype -> median trivy_g - median syft : {grype_df['grype_total_vuls_trivy_g'].median() - grype_df['grype_total_vuls_syft'].median()}")
    print(f"cve-bin-tool -> median trivy_g - median syft : {cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'].median() - cve_bin_tool_df['cve_bin_tool_total_vuls_syft'].median()}")
    print()
    print()

    print("------range of differences------")
    diff = trivy_df['trivy_total_vuls_trivy_g'] - trivy_df['trivy_total_vuls_syft']
    print(f"trivy_a -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"trivy_a -> trivy_g - syft std dev: {diff.std()}")

    diff = grype_df['grype_total_vuls_syft'] - grype_df['grype_total_vuls_trivy_g']
    print(f"grype -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"grype -> trivy_g - syft std dev: {diff.std()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_trivy_g'] - cve_bin_tool_df['cve_bin_tool_total_vuls_syft']
    print(f"cve-bin-tool -> trivy_g - syft max & min difference: max {diff.max()} min {diff.min()}")
    print(f"cve-bin-tool -> trivy_g - syft std dev: {diff.std()}")
    print()
    print()
    print("\n\n")

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner=None, cut=0, dropna=True, linewidth=0.5)
    plt.xlabel('Generation Tool', fontsize=22)
    plt.ylabel(r'Findings', fontsize=22)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=14)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='#e67bd6', lw=4, label='Syft - SPDX 2.2'),
        plt.Line2D([0], [0], color='#ffa600', lw=4, label='Trivy_G - SPDX 2.2')
    ]
    plt.legend(handles=custom_legend, loc='upper right', fontsize=16)

    sns.despine()
    plt.gca().set_facecolor('#F5F5F5')
    plt.tick_params(axis='both', which='both', length=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins/figure2-{spec}.png')
    plt.clf()
    print()
    print()

def build_figure3_1(cdx_df, spdx_df, output, gen_tool, m):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        cdx_df[column] = np.where(cdx_df[column] == -1, np.nan, cdx_df[column])
    for column in columns_to_check:
        spdx_df[column] = np.where(spdx_df[column] == -1, np.nan, spdx_df[column])
    merged_df = pd.merge(cdx_df, spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')
    merged_df = m

    columns_and_labels = {
        'trivy_total_vuls_cdx': 'CDX 1.5',
        'trivy_total_vuls_spdx': 'SPDX 2.2',
        'grype_total_vuls_cdx': '  CDX 1.5',
        'grype_total_vuls_spdx': ' SPDX 2.2',
        'cve_bin_tool_total_vuls_cdx': 'CDX 1.5 ',
        'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2 ',
    }
    columns_and_colors = {
        'trivy_total_vuls_cdx': '#6495ed',
        'trivy_total_vuls_spdx': '#e67bd6',
        'grype_total_vuls_cdx': '#6495ed',
        'grype_total_vuls_spdx': '#e67bd6',
        'cve_bin_tool_total_vuls_cdx': '#6495ed',
        'cve_bin_tool_total_vuls_spdx': '#e67bd6',
    }


    # create three new dataframes, one containgin trivy_total_vuls_cdx and trivy_total_vuls_spdx, one containing grype_total_vuls_cdx and grype_total_vuls_spdx, and one containing cve_bin_tool_total_vuls_cdx and cve_bin_tool_total_vuls_spdx
    trivy_df = merged_df[['target', 'target_version', 'trivy_total_vuls_cdx', 'trivy_total_vuls_spdx']]
    grype_df = merged_df[['target', 'target_version', 'grype_total_vuls_cdx', 'grype_total_vuls_spdx']]
    cve_bin_tool_df = merged_df[['target', 'target_version', 'cve_bin_tool_total_vuls_cdx', 'cve_bin_tool_total_vuls_spdx']]
    missing_indices = trivy_df.index[(trivy_df['trivy_total_vuls_cdx'] == -1) | (trivy_df['trivy_total_vuls_spdx'] == -1)]
    trivy_df = trivy_df.drop(missing_indices)
    missing_indices = grype_df.index[(grype_df['grype_total_vuls_cdx'] == -1) | (grype_df['grype_total_vuls_spdx'] == -1)]
    grype_df = grype_df.drop(missing_indices)
    missing_indices = cve_bin_tool_df.index[(cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] == -1) | (cve_bin_tool_df['cve_bin_tool_total_vuls_spdx'] == -1)]
    cve_bin_tool_df = cve_bin_tool_df.drop(missing_indices)



    print("################ Syft CDX versus SPDX ################")
    print("-----N------")
    print(f"trivy: {trivy_df['trivy_total_vuls_cdx'].count()}")
    print(f"grype: {grype_df['grype_total_vuls_cdx'].count()}")
    print(f"cve-bin-tool: {cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'].count()}")

    # get index of max value in grype_df['grype_total_vuls_syft']
    max_index = grype_df['grype_total_vuls_cdx'].idxmax()
    print(f"max index: {max_index}")
    print(f"target: {grype_df['target'][max_index]} {grype_df['target_version'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_cdx'][max_index]}")
    print(f"max value: {grype_df['grype_total_vuls_spdx'][max_index]}")

    print("-----% sboms with same findings------")
    diff = trivy_df['trivy_total_vuls_cdx'] - trivy_df['trivy_total_vuls_spdx']
    print(f"trivy_a - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    diff = grype_df['grype_total_vuls_cdx'] - grype_df['grype_total_vuls_spdx']
    print(f"grype - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx']
    print(f"cve-bin-tool - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    print()
    print()

    print("------differences in medians------")
    print(f"trivy_a -> median cdx - median spdx : {trivy_df['trivy_total_vuls_cdx'].median() - trivy_df['trivy_total_vuls_spdx'].median()}")
    print(f"grype -> median cdx - median spdx : {grype_df['grype_total_vuls_cdx'].median() - grype_df['grype_total_vuls_spdx'].median()}")
    print(f"cve-bin-tool -> median cdx - median spdx : {cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'].median() - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx'].median()}")
    print()
    print()

    print("------range of differences------")
    diff = trivy_df['trivy_total_vuls_spdx'] - trivy_df['trivy_total_vuls_cdx']
    print(f"trivy_a -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"trivy_a -> cdx - spdx std dev: {diff.std()}")
    diff = grype_df['grype_total_vuls_cdx'] - grype_df['grype_total_vuls_spdx']
    print(f"grype -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"grype -> cdx - spdx std dev: {diff.std()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx']
    print(f"cve-bin-tool -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"cve-bin-tool -> cdx - spdx std dev: {diff.std()}")
    print()
    print()
    print("\n\n")

    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner=None, cut=0, dropna=True, linewidth=0.5)
    plt.xlabel('Specification', fontsize=22)
    plt.ylabel(r'Findings', fontsize=22)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=14)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='#6495ed', lw=4, label='Syft - CDX 1.5'),
        plt.Line2D([0], [0], color='#e67bd6', lw=4, label='Syft - SPDX 2.2')
    ]
    plt.legend(handles=custom_legend, loc='upper right', fontsize=16)

    sns.despine()
    plt.gca().set_facecolor('#F5F5F5')
    plt.tick_params(axis='both', which='both', length=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins/figure3-{gen_tool}.png')
    plt.clf()
    print()
    print()

def build_figure3_2(cdx_df, spdx_df, output, gen_tool):
    columns_to_check = [f'trivy_total_vuls', f'grype_total_vuls', 'cve_bin_tool_total_vuls']
    for column in columns_to_check:
        cdx_df[column] = np.where(cdx_df[column] == -1, np.nan, cdx_df[column])
    for column in columns_to_check:
        spdx_df[column] = np.where(spdx_df[column] == -1, np.nan, spdx_df[column])
    merged_df = pd.merge(cdx_df, spdx_df, on=['target', 'target_version'], suffixes=(f'_cdx', f'_spdx'), how='inner')

    columns_and_labels = {
        'trivy_total_vuls_cdx': 'CDX 1.5',
        'trivy_total_vuls_spdx': 'SPDX 2.2',
        'grype_total_vuls_cdx': '  CDX 1.5',
        'grype_total_vuls_spdx': ' SPDX 2.2',
        'cve_bin_tool_total_vuls_cdx': 'CDX 1.5 ',
        'cve_bin_tool_total_vuls_spdx': 'SPDX 2.2 ',
    }
    columns_and_colors = {
        'trivy_total_vuls_cdx': '#ff717f',
        'trivy_total_vuls_spdx': '#ffa600',
        'grype_total_vuls_cdx': '#ff717f',
        'grype_total_vuls_spdx': '#ffa600',
        'cve_bin_tool_total_vuls_cdx': '#ff717f',
        'cve_bin_tool_total_vuls_spdx': '#ffa600',
    }


    # create three new dataframes, one containgin trivy_total_vuls_cdx and trivy_total_vuls_spdx, one containing grype_total_vuls_cdx and grype_total_vuls_spdx, and one containing cve_bin_tool_total_vuls_cdx and cve_bin_tool_total_vuls_spdx
    trivy_df = merged_df[['target', 'target_version', 'trivy_total_vuls_cdx', 'trivy_total_vuls_spdx']]
    grype_df = merged_df[['target', 'target_version', 'grype_total_vuls_cdx', 'grype_total_vuls_spdx']]
    cve_bin_tool_df = merged_df[['target', 'target_version', 'cve_bin_tool_total_vuls_cdx', 'cve_bin_tool_total_vuls_spdx']]
    missing_indices = trivy_df.index[(trivy_df['trivy_total_vuls_cdx'] == -1) | (trivy_df['trivy_total_vuls_spdx'] == -1)]
    trivy_df = trivy_df.drop(missing_indices)
    missing_indices = grype_df.index[(grype_df['grype_total_vuls_cdx'] == -1) | (grype_df['grype_total_vuls_spdx'] == -1)]
    grype_df = grype_df.drop(missing_indices)
    missing_indices = cve_bin_tool_df.index[(cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] == -1) | (cve_bin_tool_df['cve_bin_tool_total_vuls_spdx'] == -1)]
    cve_bin_tool_df = cve_bin_tool_df.drop(missing_indices)



    print("################ Trivy_g CDX versus SPDX ################")
    print("-----N------")
    print(f"trivy: {trivy_df['trivy_total_vuls_cdx'].count()}")
    print(f"grype: {grype_df['grype_total_vuls_cdx'].count()}")
    print(f"cve-bin-tool: {cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'].count()}")


    print("-----% sboms with same findings------")
    diff = trivy_df['trivy_total_vuls_cdx'] - trivy_df['trivy_total_vuls_spdx']
    print(f"trivy_a - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    diff = grype_df['grype_total_vuls_cdx'] - grype_df['grype_total_vuls_spdx']
    print(f"grype - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx']
    print(f"cve-bin-tool - % same cdx -> spdx : {diff[diff == 0].count() / diff.count()}")
    print()
    print()

    print("------differences in medians------")
    print(f"trivy_a -> median cdx - median spdx : {trivy_df['trivy_total_vuls_cdx'].median() - trivy_df['trivy_total_vuls_spdx'].median()}")
    print(f"grype -> median cdx - median spdx : {grype_df['grype_total_vuls_cdx'].median() - grype_df['grype_total_vuls_spdx'].median()}")
    print(f"cve-bin-tool -> median cdx - median spdx : {cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'].median() - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx'].median()}")
    print()
    print()

    print("------range of differences------")
    diff = trivy_df['trivy_total_vuls_cdx'] - trivy_df['trivy_total_vuls_spdx']
    print(f"trivy_a -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"trivy_a -> cdx - spdx std dev: {diff.std()}")
    diff = grype_df['grype_total_vuls_cdx'] - grype_df['grype_total_vuls_spdx']
    print(f"grype -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"grype -> cdx - spdx std dev: {diff.std()}")
    diff = cve_bin_tool_df['cve_bin_tool_total_vuls_cdx'] - cve_bin_tool_df['cve_bin_tool_total_vuls_spdx']
    print(f"cve-bin-tool -> cdx - spdx max & min difference: max {diff.max()} min {diff.min()}")
    print(f"cve-bin-tool -> cdx - spdx std dev: {diff.std()}")
    print()
    print()
    print("\n\n")


    plt.figure(figsize=(12, 8))
    plot_data = merged_df[list(columns_and_labels.keys())]
    melted_data = plot_data.melt(var_name='Metric', value_name='Value')
    melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)

    sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner=None, cut=0, dropna=True, linewidth=0.5)
    plt.xlabel('Specification', fontsize=22)
    plt.ylabel(r'Findings', fontsize=22)
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=14)
    plt.tight_layout()

    # Adding legend with custom labels
    custom_legend = [
        plt.Line2D([0], [0], color='#ff717f', lw=4, label='Trivy_G - CDX 1.5'),
        plt.Line2D([0], [0], color='#ffa600', lw=4, label='Trivy_G - SPDX 2.2')
    ]
    plt.legend(handles=custom_legend, loc='upper right', fontsize=16)

    sns.despine()
    plt.gca().set_facecolor('#F5F5F5')
    plt.tick_params(axis='both', which='both', length=0)
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    # Adding semi-transparent lines between specific violins
    plt.axvline(x=1.5, color='gray', alpha=0.5)  # Line between second and third violin
    plt.axvline(x=3.5, color='gray', alpha=0.5)  # Line between fourth and fifth violin

    print(f"saving SBOM all gen,analysis combos violins")
    plt.savefig(output + f'violins/figure3-{gen_tool}.png')
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

    max_vuls = 0
    max_pkgs = 0
    for filename in os.listdir(_input):
        if filename.endswith('.csv') and "compiled" in filename:
            df = pd.read_csv(_input + filename)
            max_vuls = max(max_vuls, df['trivy_total_vuls'].max(), df['grype_total_vuls'].max(), df['cve_bin_tool_total_vuls'].max())

    syft_cdx_df = pd.read_csv(_input + "compiled_results_for_sboms_syft_CDX1.5.csv")
    syft_spdx_df = pd.read_csv(_input + "compiled_results_for_sboms_syft_SPDX2.2.csv")
    trivy_cdx_df = pd.read_csv(_input + "compiled_results_for_sboms_trivy_g_CDX1.5.csv")
    trivy_spdx_df = pd.read_csv(_input + "compiled_results_for_sboms_trivy_g_SPDX2.2.csv")

    syft_cdx_spdx_df = pd.read_csv(_input + "merged_results_for_sboms_syft_spdx_and_cdx.csv")

    build_figure2_1(trivy_cdx_df, syft_cdx_df, output, "cdx", trivy_spdx_df, syft_spdx_df)
    build_figure2_2(trivy_spdx_df, syft_spdx_df, output, "spdx")
    build_figure3_1(syft_cdx_df, syft_spdx_df, output, "syft", syft_cdx_spdx_df)
    build_figure3_2(trivy_cdx_df, trivy_spdx_df, output, "trivy_g")
    plt.close('all')


    print("finish")


main()































# def build_violin_gen_tool(t_df, s_df, output, spec, severity):
#     t_df = t_df[(t_df[f'trivy_{severity}_vuls'] != -1) & (t_df[f'grype_{severity}_vuls'] != -1) & (t_df['num_components'] != -1) & (t_df['cve_bin_tool_total_vuls'] != -1)]
#     s_df = s_df[(s_df[f'trivy_{severity}_vuls'] != -1) & (s_df[f'grype_{severity}_vuls'] != -1) & (s_df['num_components'] != -1) & (s_df['cve_bin_tool_total_vuls'] != -1)]
#     merged_df = pd.merge(t_df, s_df, on=['target', 'target_version'], suffixes=(f'_trivy_g', f'_syft'), how='inner')
#     merged_df.to_csv(output + f"violins/merged_results_{spec}_trivy-versus-syft.csv", index=False)
#
#
#     columns_and_labels = {
#         'trivy_total_vuls_trivy_g': 'G: Trivy A: Trivy',
#         'trivy_total_vuls_syft': 'G: Syft A: Trivy',
#         'grype_total_vuls_trivy_g': 'G: Trivy A: Grype',
#         'grype_total_vuls_syft': 'G: Syft A: Grype',
#         'cve_bin_tool_total_vuls_trivy_g': 'G: Trivy A: CVE-bin-tool',
#         'cve_bin_tool_total_vuls_syft': 'G: Syft A: CVE-bin-tool'
#     }
#     columns_and_colors = {
#         'trivy_total_vuls_trivy_g': 'orange',
#         'trivy_total_vuls_syft': 'cornflowerblue',
#         'grype_total_vuls_trivy_g': 'orange',
#         'grype_total_vuls_syft': 'cornflowerblue',
#         'cve_bin_tool_total_vuls_trivy_g': 'orange',
#         'cve_bin_tool_total_vuls_syft': 'cornflowerblue'
#     }
#
#     plt.figure(figsize=(12, 8))
#     plot_data = merged_df[list(columns_and_labels.keys())]
#     melted_data = plot_data.melt(var_name='Metric', value_name='Value')
#     melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)
#
#     sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
#     plt.xlabel('SBOM Generation tool used & Analysis Tool used', fontsize=18)
#     plt.ylabel(r'Findings', fontsize=18)
#     #plt.title(f'Vulnerability Findings for each Generation Tool and Analysis Tool pair')
#     print(f"saving SBOM all gen,analysis combos violins")
#     plt.savefig(output + f'violins/sbom_{spec}--trivy_g-trivy__syft-trivy__trivy_g-grype__syft-grype__cve-bin-tool.png')
#     plt.clf()
#     print()
#     print()
#
#
#
#     columns_and_labels = {
#         'num_components_trivy_g': 'G: Trivy',
#         'num_components_syft': 'G: Syft',
#     }
#     columns_and_colors = {
#         'num_components_trivy_g': 'orange',
#         'num_components_syft': 'cornflowerblue',
#     }
#
#     plt.figure(figsize=(12, 8))
#     plot_data = merged_df[list(columns_and_labels.keys())]
#     melted_data = plot_data.melt(var_name='Metric', value_name='Value')
#     melted_data['Metric'] = melted_data['Metric'].map(columns_and_labels)
#
#     sns.violinplot(x='Metric', y='Value', data=melted_data, palette=columns_and_colors.values(), inner="quartile")
#     plt.xlabel('SBOM Generation tool used', fontsize=14)
#     plt.ylabel(r'# Components', fontsize=14)
#     plt.title(f'# Components for each Generation Tool and Analysis Tool pair')
#     print(f"saving SBOM all gen,num_comps combos violins")
#     plt.savefig(output + f'violins/sbom_{spec}--trivy_g-num_comps__syft-num_comps.png')
#     plt.clf()
#     print()
#     print()
