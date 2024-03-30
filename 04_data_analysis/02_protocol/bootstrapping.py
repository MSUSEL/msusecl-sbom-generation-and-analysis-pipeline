import pandas as pd
import numpy as np
import argparse

def calculate_cohens_d(sample1, sample2):
    pooled_std = np.sqrt((np.var(sample1) + np.var(sample2)) / 2)
    cohens_d = np.abs(np.mean(sample1) - np.mean(sample2)) / pooled_std
    return cohens_d

def bootstrap(sample1, sample2, analysis_tool, comparison, constant):
    print(f"##### {comparison} in {constant} analyzed with {analysis_tool} #####")

    missing_indices = sample1.index[(sample1 == -1) | (sample2 == -1)]
    sample1 = sample1.drop(missing_indices)
    sample2 = sample2.drop(missing_indices)
    sample = sample1 - sample2

    # Set the number of bootstrap samples
    num_bootstraps = 20000
    sample_size = len(sample) - 1

    # Initialize an empty array to store bootstrap statistics
    bootstrap_estimates = np.zeros(num_bootstraps)

    # Perform bootstrapping
    for i in range(num_bootstraps):
        # Generate bootstrap samples by resampling with replacement
        bootstrap_sample = np.random.choice(sample, size=sample_size, replace=True)

        # Compute the point estimate for the bootstrap sample (e.g., difference in means)
        bootstrap_estimate = np.mean(bootstrap_sample)

        # Store the bootstrap estimate
        bootstrap_estimates[i] = bootstrap_estimate


    # Calculate confidence intervals
    confidence_interval = np.percentile(bootstrap_estimates, [2.5, 97.5])

    # Print results
    print(f"Bootstrap Point Estimate: {np.mean(bootstrap_estimates)}")
    print(f"95% Confidence Interval: {confidence_interval}")


    return np.mean(bootstrap_estimates), confidence_interval


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    row_names = ['Trivy_g versus Syft (CDX)', 'Trivy_g versus Syft (SPDX)', 'CDX versus SPDX (Trivy_g)', 'CDX versus SPDX (Syft)']
    column_names = ['Trivy_a', 'Grype', 'CVE-bin-tool', 'Num_comps']

    # Create an empty DataFrame with row and column names
    results = pd.DataFrame(index=row_names, columns=column_names)

    df = pd.read_csv(_input + "merged_results_for_sboms_cdx1.5_trivy-g_and_syft.csv")
    t_pe, t_ci = bootstrap(df["trivy_total_vuls_trivy_g"], df["trivy_total_vuls_syft"], "Trivy", "Trivy_g versus Syft", "CDX 1.5")
    t_cd = calculate_cohens_d(df["trivy_total_vuls_trivy_g"], df["trivy_total_vuls_syft"])
    print(f"Cohen's d: {t_cd}")
    print("\n\n")
    g_pe, g_ci = bootstrap(df["grype_total_vuls_trivy_g"], df["grype_total_vuls_syft"], "Grype", "Trivy_g versus Syft", "CDX 1.5")
    g_cd = calculate_cohens_d(df["grype_total_vuls_trivy_g"], df["grype_total_vuls_syft"])
    print(f"Cohen's d: {g_cd}")
    print("\n\n")
    c_pe, c_ci = bootstrap(df["cve_bin_tool_total_vuls_trivy_g"], df["cve_bin_tool_total_vuls_syft"], "CVE-bin-tool", "Trivy_g versus Syft", "CDX 1.5")
    c_cd = calculate_cohens_d(df["cve_bin_tool_total_vuls_trivy_g"], df["cve_bin_tool_total_vuls_syft"])
    print(f"Cohen's d: {c_cd}")
    print("\n\n")
    n_pe, n_ci = bootstrap(df["num_components_trivy_g"], df["num_components_syft"], "Number of Components", "Trivy_g versus Syft", "CDX 1.5")
    n_cd = calculate_cohens_d(df["num_components_trivy_g"], df["num_components_syft"])
    print(f"Cohen's d: {n_cd}")
    print("\n\n")

    t_formatted = f"est:{round(t_pe, 3)} conf_int:{round(t_ci[0],3)}_{round(t_ci[1],3)}"
    g_formatted = f"est:{round(g_pe, 3)} conf_int:{round(g_ci[0],3)}_{round(g_ci[1],3)}"
    c_formatted = f"est:{round(c_pe, 3)} conf_int:{round(c_ci[0],3)}_{round(c_ci[1],3)}"
    n_formatted = f"est:{round(n_pe, 3)} conf_int:{round(n_ci[0],3)}_{round(n_ci[1],3)}"
    results.iloc[0, 0:4] = [t_formatted, g_formatted, c_formatted, n_formatted]


    print("##########################################################################################\n\n")

    df = pd.read_csv(_input + "merged_results_for_sboms_spdx2.2_trivy-g_and_syft.csv")
    t_pe, t_ci = bootstrap(df["trivy_total_vuls_trivy_g"], df["trivy_total_vuls_syft"], "Trivy", "Trivy_g versus Syft", "SPDX 2.2")
    t_cd = calculate_cohens_d(df["trivy_total_vuls_trivy_g"], df["trivy_total_vuls_syft"])
    print(f"Cohen's d: {t_cd}")
    print("\n\n")
    g_pe, g_ci = bootstrap(df["grype_total_vuls_trivy_g"], df["grype_total_vuls_syft"], "Grype", "Trivy_g versus Syft", "SPDX 2.2")
    g_cd = calculate_cohens_d(df["grype_total_vuls_trivy_g"], df["grype_total_vuls_syft"])
    print(f"Cohen's d: {g_cd}")
    print("\n\n")
    c_pe, c_ci = bootstrap(df["cve_bin_tool_total_vuls_trivy_g"], df["cve_bin_tool_total_vuls_syft"], "CVE-bin-tool", "Trivy_g versus Syft", "SPDX 2.2")
    c_cd = calculate_cohens_d(df["cve_bin_tool_total_vuls_trivy_g"], df["cve_bin_tool_total_vuls_syft"])
    print(f"Cohen's d: {c_cd}")
    print("\n\n")
    n_pe, n_ci = bootstrap(df["num_components_trivy_g"], df["num_components_syft"], "Number of Components", "Trivy_g versus Syft", "SPDX 2.2")
    n_cd = calculate_cohens_d(df["num_components_trivy_g"], df["num_components_syft"])
    print(f"Cohen's d: {n_cd}")
    print("\n\n")
    t_formatted = f"est:{round(t_pe, 3)} conf_int:{round(t_ci[0],3)}_{round(t_ci[1],3)}"
    g_formatted = f"est:{round(g_pe, 3)} conf_int:{round(g_ci[0],3)}_{round(g_ci[1],3)}"
    c_formatted = f"est:{round(c_pe, 3)} conf_int:{round(c_ci[0],3)}_{round(c_ci[1],3)}"
    n_formatted = f"est:{round(n_pe, 3)} conf_int:{round(n_ci[0],3)}_{round(n_ci[1],3)}"
    results.iloc[1, 0:4] = [t_formatted, g_formatted, c_formatted, n_formatted]

    print("##########################################################################################\n\n")

    df = pd.read_csv(_input + "merged_results_for_sboms_trivy_g_spdx_and_cdx.csv")
    t_pe, t_ci = bootstrap(df["trivy_total_vuls_spdx"], df["trivy_total_vuls_cdx"], "Trivy", "SPDX versus CDX", "Trivy_g")
    t_cd = calculate_cohens_d(df["trivy_total_vuls_spdx"], df["trivy_total_vuls_cdx"])
    print(f"Cohen's d: {t_cd}")
    print("\n\n")
    g_pe, g_ci = bootstrap(df["grype_total_vuls_spdx"], df["grype_total_vuls_cdx"], "Grype", "SPDX versus CDX", "Trivy_g")
    g_cd = calculate_cohens_d(df["grype_total_vuls_spdx"], df["grype_total_vuls_cdx"])
    print(f"Cohen's d: {g_cd}")
    print("\n\n")
    c_pe, c_ci = bootstrap(df["cve_bin_tool_total_vuls_spdx"], df["cve_bin_tool_total_vuls_cdx"], "CVE-bin-tool", "SPDX versus CDX", "Trivy_g")
    c_cd = calculate_cohens_d(df["cve_bin_tool_total_vuls_spdx"], df["cve_bin_tool_total_vuls_cdx"])
    print(f"Cohen's d: {c_cd}")
    print("\n\n")
    n_pe, n_ci = bootstrap(df["num_components_spdx"], df["num_components_cdx"], "Number of Components", "SPDX versus CDX", "Trivy_g")
    n_cd = calculate_cohens_d(df["num_components_spdx"], df["num_components_cdx"])
    print(f"Cohen's d: {n_cd}")
    print("\n\n")
    t_formatted = f"est:{round(t_pe, 3)} conf_int:{round(t_ci[0],3)}_{round(t_ci[1],3)}"
    g_formatted = f"est:{round(g_pe, 3)} conf_int:{round(g_ci[0],3)}_{round(g_ci[1],3)}"
    c_formatted = f"est:{round(c_pe, 3)} conf_int:{round(c_ci[0],3)}_{round(c_ci[1],3)}"
    n_formatted = f"est:{round(n_pe, 3)} conf_int:{round(n_ci[0],3)}_{round(n_ci[1],3)}"
    results.iloc[2, 0:4] = [t_formatted, g_formatted, c_formatted, n_formatted]

    print("##########################################################################################\n\n")

    df = pd.read_csv(_input + "merged_results_for_sboms_syft_spdx_and_cdx.csv")
    t_pe, t_ci = bootstrap(df["trivy_total_vuls_spdx"], df["trivy_total_vuls_cdx"], "Trivy", "SPDX versus CDX", "Syft")
    t_cd = calculate_cohens_d(df["trivy_total_vuls_spdx"], df["trivy_total_vuls_cdx"])
    print(f"Cohen's d: {t_cd}")
    print("\n\n")
    g_pe, g_ci = bootstrap(df["grype_total_vuls_spdx"], df["grype_total_vuls_cdx"], "Grype", "SPDX versus CDX", "Syft")
    g_cd = calculate_cohens_d(df["grype_total_vuls_spdx"], df["grype_total_vuls_cdx"])
    print(f"Cohen's d: {g_cd}")
    print("\n\n")
    c_pe, c_ci = bootstrap(df["cve_bin_tool_total_vuls_spdx"], df["cve_bin_tool_total_vuls_cdx"], "CVE-bin-tool", "SPDX versus CDX", "Syft")
    c_cd = calculate_cohens_d(df["cve_bin_tool_total_vuls_spdx"], df["cve_bin_tool_total_vuls_cdx"])
    print(f"Cohen's d: {c_cd}")
    print("\n\n")
    n_pe, n_ci = bootstrap(df["num_components_spdx"], df["num_components_cdx"], "Number of Components", "SPDX versus CDX", "Syft")
    n_cd = calculate_cohens_d(df["num_components_spdx"], df["num_components_cdx"])
    print(f"Cohen's d: {n_cd}")
    print("\n\n")
    t_formatted = f"est:{round(t_pe, 3)} conf_int:{round(t_ci[0],3)}_{round(t_ci[1],3)}"
    g_formatted = f"est:{round(g_pe, 3)} conf_int:{round(g_ci[0],3)}_{round(g_ci[1],3)}"
    c_formatted = f"est:{round(c_pe, 3)} conf_int:{round(c_ci[0],3)}_{round(c_ci[1],3)}"
    n_formatted = f"est:{round(n_pe, 3)} conf_int:{round(n_ci[0],3)}_{round(n_ci[1],3)}"
    results.iloc[3, 0:4] = [t_formatted, g_formatted, c_formatted, n_formatted]

    results.to_csv(output + "bootstrap_results.csv")



if __name__ == "__main__":
    main()
