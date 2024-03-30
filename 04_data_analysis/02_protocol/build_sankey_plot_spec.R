library(dplyr)
library(tibble)
library(purrr)
library(readr)
library(patchwork)
library(tidyr)
library(ggplot2)
library(ggalluvial)
library(tidyselect)
library(egg)
library(ggpubr)
library(stringr)
library(RColorBrewer)


# Calculate Jenks natural breaks for a set of findings
calc_jenks_breaks <-
  function(longDf, ngroups){
    # you need one more break than groups
    nbreaks <- ngroups + 1
    # make a vector from the column in your long dataframe that contains the
    # findings (for you, this is the vulnerabilities or packages in the sboms)
    findings_vector <-
      longDf[,'findings_count'] %>%
      unlist()
    # do the 1-d clustering on your vector of findings (ie calculate the breaks)
    breaks <-
      findings_vector %>%
      BAMMtools::getJenksBreaks(k= nbreaks)
    # create a list containing the lower and upper bounds for the breaks
    breaks_list <-
      mapply(
        function(i, j) {
          lower <- ifelse(i == 1, min(breaks), breaks[i])
          upper <- ifelse(j == nbreaks, max(breaks), breaks[j]-1)
          c(lower, upper)
        },
        1:ngroups, 2:nbreaks,
        SIMPLIFY = FALSE
      )
    names(breaks_list) <- LETTERS[length(breaks_list):1]
    # take the list above and make a df from the info therein
    breaks_df <- do.call(rbind, breaks_list) %>%
      as.data.frame()
    names(breaks_df) <- c("lowerbound", "upperbound")
    # fill in the group based on the jenks breaks
    out <-
      sapply(
        findings_vector,
        function(finding_score){
          grp <-
            row.names(breaks_df)[finding_score >= breaks_df$lowerbound &
                                   finding_score <= breaks_df$upperbound]
          return(grp)
        }
      )
    # make a new column in your long data frame that is the group and ensure
    # that the group is saved as a "factor" data type
    longDf$group <- factor(unlist(out))
    # rename the version (whatever your x axis is) to sank_column
    names(longDf)[names(longDf) == "gen_tool"] <- "sank_column"
    # make a new column that is the range in the findings (this is so you can
    # make a pretty legend later)
    breaks_df$findings_range <-
      paste(breaks_df$lowerbound, breaks_df$upperbound, sep = " - ")
    # make a new column with the group in the breaks df
    breaks_df$group <- factor(row.names(breaks_df))
    # join the breaks_df to the longDf based on the "group"
    longDf <- left_join(longDf, breaks_df, by = "group")
    # return the new longDf
    return(longDf)
  }


# Calculate jenks natural breaks for findings of a static analysis tool.  Plot
# the results (score groups across versions) in a sankey plot.
sankey_jenks_cust <- function(findings_dat_long){
  new_rows <- data.frame(
    name = c("temp1", "temp2"),
    sank_column = c("CDX 1.5", "SPDX 2.2"),
    findings_count = c(-1, -1),
    group = c("C", "B"),
    lowerbound = c(4357, 2916),
    upperbound = c(6451, 4356),
    findings_range = c("4357 - 6451", "2916 - 4356")
  )
  findings_dat_long <- rbind(findings_dat_long, new_rows)
  myLabels <-
    unique(findings_dat_long$findings_range)[
      order(unique(findings_dat_long$lowerbound))
    ] %>%
    rev()
  print(myLabels)
  #findings_dat_long <- findings_dat_long[findings_dat_long$findings_count == -999, ]
  unique_names <- unique(findings_dat_long$name)
  unique_names <- unique(findings_dat_long$name)
  max_value <- length(unique_names)
  
  y_breaks <- seq(0, max_value, by = 500)  # Adjust the step as needed
  y_labels <- y_breaks[y_breaks <= max_value]
  
  p <-
    ggplot(aes(x = sank_column, stratum = group, alluvium = name,
               fill = group, label = group), data = findings_dat_long) +
    geom_flow(stat = "alluvium",
              lode.guidance = "frontback",
              alpha = 0.4) +
    geom_stratum() +
    scale_y_continuous(breaks = y_breaks, labels = y_labels) +
    theme(
      legend.position = "none",
      text = element_text(size = 14),
      axis.text = element_text(size = 10),
      axis.text.x = element_text(angle = 40, hjust=1),
      legend.title = element_text(size = 10),
      legend.text = element_text(size = 10),
      legend.margin = margin(t =-10),
      legend.key.size = unit(0.4, "cm"),
      panel.grid.major = element_blank(),
      panel.grid.minor = element_blank(),
      # plot.margin = unit(c(-5, 5, 0, 1), "pt")
      plot.margin = unit(c(0, 5, 0, 1), "pt"),
      plot.title = element_text(vjust = -5.0),
      panel.background = element_rect(fill = "transparent")
    ) +
    scale_fill_viridis_d(
      labels = myLabels, 
      direction = -1,
      option = "plasma"
    ) +
    guides(
      fill = guide_legend(
        # title="Findings Range",
        title = element_blank(),
        # title.hjust = 0.5,
        nrow =4,
        byrow = TRUE,
        reverse = TRUE
      )
    )+
    ###### ERIC CHANGE THE LABELS ############
  labs(x="", y= "SBOM")+
    scale_x_discrete(expand = expansion(c(0,0)))
  p
}

sankey_jenks_cust_cbt <- function(findings_dat_long){
  new_rows <- data.frame(
    name = c("temp1", "temp2"),
    sank_column = c("CDX 1.5", "SPDX 2.2"),
    findings_count = c(-1, -1),
    group = c("C", "B"),
    lowerbound = c(4357, 2916),
    upperbound = c(6451, 4356),
    findings_range = c("4357 - 6451", "2916 - 4356")
  )
  findings_dat_long <- rbind(findings_dat_long, new_rows)
  myLabels <-
    unique(findings_dat_long$findings_range)[
      order(unique(findings_dat_long$lowerbound))
    ] %>%
    rev()
  print(myLabels)
  #findings_dat_long <- findings_dat_long[findings_dat_long$findings_count != -999, ]
  
  # get count for how many unique names there are
  unique_names <- unique(findings_dat_long$name)
  max_value <- length(unique_names)

  y_breaks <- seq(0, max_value, by = 500)  # Adjust the step as needed
  y_labels <- y_breaks[y_breaks <= max_value]
  
  p <-
    ggplot(aes(x = sank_column, stratum = group, alluvium = name,
               fill = group, label = group), data = findings_dat_long) +
    geom_flow(stat = "alluvium",
              lode.guidance = "frontback",
              alpha = 0.4) +
    geom_stratum() +
    scale_y_continuous(breaks = y_breaks, labels = y_labels) +
    theme(
      legend.position = "none",
      text = element_text(size = 14),
      axis.text = element_text(size = 10),
      axis.text.x = element_text(angle = 40, hjust=1),
      legend.title = element_text(size = 10),
      legend.text = element_text(size = 10),
      legend.margin = margin(t =-10),
      legend.key.size = unit(0.4, "cm"),
      panel.grid.major = element_blank(),
      panel.grid.minor = element_blank(),
      #panel.background = element_blank(),
      # plot.margin = unit(c(-5, 5, 0, 1), "pt")
      plot.margin = unit(c(0, 5, 0, 1), "pt"),
      plot.title = element_text(vjust = -5.0),
      panel.background = element_rect(fill = "transparent")
    ) +
    scale_fill_viridis_d(
      labels = myLabels, 
      direction = -1,
      option = "plasma"
    ) +
    guides(
      fill = guide_legend(
        # title="Findings Range",
        title = element_blank(),
        # title.hjust = 0.5,
        nrow =4,
        byrow = TRUE,
        reverse = TRUE
      )
    )+
    ###### ERIC CHANGE THE LABELS ############
  labs(x="", y= "SBOM")+
    scale_x_discrete(expand = expansion(c(0,0)))
  p
}

# Calculate jenks natural breaks for findings of a static analysis tool.  Plot
# the results (score groups across versions) in a sankey plot.
sankey_jenks_cust_custom <- function(findings_dat_long){
  new_rows <- data.frame(
    name = c("temp1", "temp2"),
    sank_column = c("CDX 1.5", "SPDX 2.2"),
    findings_count = c(-1, -1),
    group = c("C", "B"),
    lowerbound = c(4357, 2916),
    upperbound = c(6451, 4356),
    findings_range = c("4357 - 6451", "2916 - 4356")
  )
  findings_dat_long <- rbind(findings_dat_long, new_rows)
  #make pretty labels and put them in order (using some really ugly code)
  myLabels <-
    unique(findings_dat_long$findings_range)[
      order(unique(findings_dat_long$lowerbound))
    ] %>%
    rev()
  print(myLabels)
  
  unique_names <- unique(findings_dat_long$name)
  unique_names <- unique(findings_dat_long$name)
  max_value <- length(unique_names)
  
  y_breaks <- seq(0, max_value, by = 500)  # Adjust the step as needed
  y_labels <- y_breaks[y_breaks <= max_value]
  
  p <-
    ggplot(aes(x = sank_column, stratum = group, alluvium = name,
               fill = group, label = group), data = findings_dat_long) +
    geom_flow(stat = "alluvium",
              lode.guidance = "frontback",
              alpha = 0.4) +
    geom_stratum() +
    scale_y_continuous(breaks = y_breaks, labels = y_labels) +
    theme(
      legend.position = "none",
      text = element_text(size = 14),
      axis.text = element_text(size = 10),
      axis.text.x = element_text(angle = 40, hjust=1),
      legend.title = element_text(size = 10),
      legend.text = element_text(size = 10),
      legend.justification = "center",
      legend.margin = margin(t =-10),
      legend.key.size = unit(0.4, "cm"),
      panel.grid.major = element_blank(),
      panel.grid.minor = element_blank(),
      #panel.background = element_blank(),
      # plot.margin = unit(c(-5, 5, 0, 1), "pt")
      plot.margin = unit(c(0, 5, 0, 1), "pt"),
      plot.title = element_text(vjust = -5.0),
      panel.background = element_rect(fill = "transparent")
    ) +
    scale_fill_viridis_d(
      labels = myLabels, 
      direction = -1,
      option = "plasma"
    ) +
    guides(
      fill = guide_legend(
        # title="Findings Range",
        title = element_blank(),
        # title.hjust = 0.5,
        nrow =4,
        byrow = TRUE,
        reverse = TRUE
      )
    )+
    ###### ERIC CHANGE THE LABELS ############
  labs(x="", y= "SBOM")+
    scale_x_discrete(expand = expansion(c(0,0)))
  p
}


create_sankey_plot <- function(df, title) {
  p <- df %>%
    sankey_jenks_cust() +
    ggtitle(title) +
    theme(plot.title = element_text(hjust = 0.5))
  return(p)
}
create_sankey_plot_cbt <- function(df, title) {
  p <- df %>%
    sankey_jenks_cust_cbt() +
    ggtitle(title) +
    theme(plot.title = element_text(hjust = 0.5))
  return(p)
}
create_sankey_plot_custom <- function(df, title) {
  p <- df %>%
    sankey_jenks_cust_custom() +
    ggtitle(title) +
    theme(plot.title = element_text(hjust = 0.5))
  return(p)
}
count_same_group <- function(df1, df2) {
  # Get unique names from df_syft
  unique_names <- unique(df1$name)
  
  # Initialize counter
  same_group_count <- 0
  
  # Loop through each unique name
  for (name in unique_names) {
    # Check if the name exists in both dataframes
    if (name %in% df1$name && name %in% df2$name) {
      # Get the groups for the current name in both dataframes
      group_syft <- df1$group[df1$name == name]
      group_trivy <- df2$group[df2$name == name]
      
      # Check if the groups are the same
      if (all(group_syft == group_trivy)) {
        # If groups are the same, increment the counter
        same_group_count <- same_group_count + 1
      }
    }
  }
  
  return(same_group_count)
}
########################################################################################################################3
# Read all CSV files and combine the data
df_trivy_trivy <- read_csv("04_preprocessing/04_product/long_df_trivy_g_trivy_vul_findings.csv")
df_grype_trivy <- read_csv("04_preprocessing/04_product/long_df_trivy_g_grype_vul_findings.csv")
df_cve_bin_tool_trivy <- read_csv("04_preprocessing/04_product/long_df_trivy_g_cve_bin_tool_vul_findings.csv")
df_trivy_trivy <- df_trivy_trivy[!(df_trivy_trivy$findings_count == '-1'), ]
df_grype_trivy <- df_grype_trivy[!(df_grype_trivy$findings_count == '-1'), ]
df_cve_bin_tool_trivy <- df_cve_bin_tool_trivy[!(df_cve_bin_tool_trivy$findings_count == '-1'), ]

# Read all CSV files and combine the data
df_trivy_syft <- read_csv("04_preprocessing/04_product/long_df_syft_trivy_vul_findings.csv")
df_grype_syft <- read_csv("04_preprocessing/04_product/long_df_syft_grype_vul_findings.csv")
df_cve_bin_tool_syft <- read_csv("04_preprocessing/04_product/long_df_syft_cve_bin_tool_vul_findings.csv")
df_trivy_syft <- df_trivy_syft[!(df_trivy_syft$findings_count == '-1'), ]
df_grype_syft <- df_grype_syft[!(df_grype_syft$findings_count == '-1'), ]
df_cve_bin_tool_syft <- df_cve_bin_tool_syft[!(df_cve_bin_tool_syft$findings_count == '-1'), ]

# Combine all dataframes
combined_df <- bind_rows(df_trivy_trivy, df_grype_trivy, df_cve_bin_tool_trivy, df_trivy_syft, df_grype_syft, df_cve_bin_tool_syft)

# Calculate Jenks breaks for the combined data
jenks_breaks_df <- combined_df %>%
  calc_jenks_breaks(8)

# Determine the number of rows in each original DataFrame
n_trivy_trivy <- nrow(df_trivy_trivy)
n_grype_trivy <- nrow(df_grype_trivy)
n_cve_bin_tool_trivy <- nrow(df_cve_bin_tool_trivy)

n_trivy_syft <- nrow(df_trivy_syft)
n_grype_syft <- nrow(df_grype_syft)
n_cve_bin_tool_syft <- nrow(df_cve_bin_tool_syft)

# Split the jenks_breaks_df back into separate DataFrames
df_trivy_trivy <- jenks_breaks_df[1:n_trivy_trivy, ]
df_grype_trivy <- jenks_breaks_df[(n_trivy_trivy + 1):(n_trivy_trivy + n_grype_trivy), ]
df_cve_bin_tool_trivy <- jenks_breaks_df[(n_trivy_trivy + n_grype_trivy + 1):(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy), ]

df_trivy_syft <- jenks_breaks_df[(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + 1):(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + n_trivy_syft), ]
df_grype_syft <- jenks_breaks_df[(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + n_trivy_syft + 1):(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + n_trivy_syft + n_grype_syft), ]
df_cve_bin_tool_syft <- jenks_breaks_df[(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + n_trivy_syft + n_grype_syft + 1):(n_trivy_trivy + n_grype_trivy + n_cve_bin_tool_trivy + n_trivy_syft + n_grype_syft + n_cve_bin_tool_syft), ]

# df_syft_cbt <- subset(df_cve_bin_tool, sank_column == "CDX 1.5")
# df_trivy_cbt <- subset(df_cve_bin_tool, sank_column == "SPDX 2.2")
# result <- count_same_group(df_syft_cbt, df_trivy_cbt)
# # Print the result
# print("Percent of SBOMs with the same group:")
# print(result)
# print(length(unique(df_cve_bin_tool$name)))
# print(result / length(unique(df_cve_bin_tool$name)))

titles <- c(expression(Trivy[A]), "Grype", "CVE Bin Tool")
counts <- c(2304, 2309, 1949)
titles[1] <- expression(atop(paste("Trivy"[A]), paste("n = 2304")))
titles[2] <- expression(atop(paste("Grype"), paste("n = 2309")))
titles[3] <- expression(atop(paste("CVE-bin-tool"), paste("n = 1949")))

sankey_plots <- list()
sankey_plots[[1]] <- create_sankey_plot_custom(df_trivy_trivy, titles[1])
sankey_plots[[2]] <- create_sankey_plot(df_grype_trivy, titles[2])
sankey_plots[[3]] <- create_sankey_plot_cbt(df_cve_bin_tool_trivy, titles[3])

combined_plot <- wrap_plots(sankey_plots)

ggsave(filename = "05_data_analysis/04_product/sankey/combined_sankey_plots_cdx_vs_spdx_trivy_g.png", plot = combined_plot, width=7, height=7)

counts <- c(2307, 2309, 1949)
titles[1] <- expression(atop(paste("Trivy"[A]), paste("n = 2307")))
titles[2] <- expression(atop(paste("Grype"), paste("n = 2309")))
titles[3] <- expression(atop(paste("CVE-bin-tool"), paste("n = 1949")))
sankey_plots <- list()
sankey_plots[[1]] <- create_sankey_plot_custom(df_trivy_syft, titles[1])
sankey_plots[[2]] <- create_sankey_plot(df_grype_syft, titles[2])
sankey_plots[[3]] <- create_sankey_plot_cbt(df_cve_bin_tool_syft, titles[3])

combined_plot <- wrap_plots(sankey_plots)

ggsave(filename = "05_data_analysis/04_product/sankey/combined_sankey_plots_cdx_vs_spdx_syft.png", plot = combined_plot, width=7, height=7)


#################################################################################################

