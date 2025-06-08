use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::fs;
use std::io::{self, Write};
use std::process;
use tabled::{Table, Tabled};

#[derive(Debug, Deserialize)]
struct SyftOutput {
    artifacts: Option<Vec<Artifact>>,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "type")]
    artifact_type: Option<String>,
    licenses: Option<Vec<SyftLicense>>,
    #[serde(rename = "purl")]
    package_url: Option<String>,
    language: Option<String>,
    #[serde(flatten)]
    other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SyftLicense {
    Simple(String),
    Detailed {
        value: Option<String>,
        #[serde(rename = "spdxExpression")]
        spdx_expression: Option<String>,
        #[serde(rename = "type")]
        license_type: Option<String>,
        #[serde(flatten)]
        other: HashMap<String, serde_json::Value>,
    },
}

#[derive(Debug, Serialize, Tabled)]
struct CsvRecord {
    name: String,
    version: String,
    #[tabled(rename = "Type")]
    artifact_type: String,
    licenses: String,
}

struct Args {
    input_file: String,
    csv_output: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        return Err(format!(
            "Usage: {} -f <input.json> [--csv <output.csv>]\n\
             \n\
             Options:\n\
             -f <file>        Input Syft JSON file\n\
             --csv <file>     Export to CSV file (optional, prints table if not specified)",
            args[0]
        ));
    }

    let mut input_file = None;
    let mut csv_output = None;
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-f" => {
                if i + 1 >= args.len() {
                    return Err("Missing filename after -f".to_string());
                }
                input_file = Some(args[i + 1].clone());
                i += 2;
            }
            "--csv" => {
                if i + 1 >= args.len() {
                    return Err("Missing filename after --csv".to_string());
                }
                csv_output = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]));
            }
        }
    }

    match input_file {
        Some(file) => Ok(Args {
            input_file: file,
            csv_output,
        }),
        None => Err("Input file (-f) is required".to_string()),
    }
}

fn extract_syft_license_info(licenses: &Option<Vec<SyftLicense>>) -> String {
    match licenses {
        Some(license_vec) => {
            let license_strings: Vec<String> = license_vec
                .iter()
                .filter_map(|license| {
                    let license_str = match license {
                        SyftLicense::Simple(license_str) => Some(license_str.clone()),
                        SyftLicense::Detailed {
                            value,
                            spdx_expression,
                            license_type: _,
                            other: _
                        } => {
                            spdx_expression.clone()
                                .or_else(|| value.clone())
                        }
                    };

                    // Filter out empty strings and trim whitespace
                    license_str.and_then(|s| {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    })
                })
                .collect();

            if license_strings.is_empty() {
                "None".to_string()
            } else {
                license_strings.join("\n")
            }
        }
        None => "None".to_string(),
    }
}

fn split_license_expression(license_expr: &str) -> Vec<String> {
    // Split by common SPDX operators: AND, OR, WITH
    // Handle parentheses by treating them as word boundaries
    license_expr
        .split(&[' ', '(', ')'][..])
        .filter_map(|part| {
            let trimmed = part.trim();
            // Skip empty parts and SPDX operators
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("AND")
                || trimmed.eq_ignore_ascii_case("OR")
                || trimmed.eq_ignore_ascii_case("WITH") {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect()
}

fn print_table(records: &[CsvRecord]) {
    if records.is_empty() {
        println!("No artifacts found.");
        return;
    }

    let table = Table::new(records);
    println!("{}", table);
    println!("\nTotal artifacts: {}", records.len());
}

fn write_csv<W: Write>(writer: W, records: &[CsvRecord]) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_writer(writer);

    // Write header
    wtr.write_record(&["Name", "Version", "Type", "Licenses"])?;

    // Write records
    for record in records {
        wtr.serialize(record)?;
    }

    wtr.flush()?;
    Ok(())
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Read the JSON file
    let json_content = match fs::read_to_string(&args.input_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Error reading file {}: {}", args.input_file, e);
            process::exit(1);
        }
    };

    // Parse the JSON
    let syft_output: SyftOutput = match serde_json::from_str(&json_content) {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Error parsing Syft JSON: {}", e);
            eprintln!("Make sure this is a valid Syft JSON output file");
            process::exit(1);
        }
    };

    // Extract artifacts
    let artifacts = match syft_output.artifacts {
        Some(artifacts) => artifacts,
        None => {
            eprintln!("No artifacts found in Syft output");
            process::exit(1);
        }
    };

    // Convert to CSV records
    let csv_records: Vec<CsvRecord> = artifacts
        .iter()
        .map(|artifact| {
            let licenses_raw = extract_syft_license_info(&artifact.licenses);

            // Process licenses: split complex expressions and handle different separators
            let all_licenses: Vec<String> = licenses_raw
                .split('\n')
                .flat_map(|license_line| {
                    let trimmed = license_line.trim();
                    if trimmed.is_empty() || trimmed == "None" {
                        vec![]
                    } else if trimmed.contains(" AND ") || trimmed.contains(" OR ") || trimmed.contains(" WITH ") {
                        // Handle SPDX expressions with AND/OR/WITH operators
                        split_license_expression(trimmed)
                    } else if trimmed.contains(';') {
                        // Handle semicolon-separated licenses
                        trimmed.split(';')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    } else {
                        // Single license
                        vec![trimmed.to_string()]
                    }
                })
                .filter(|s| !s.is_empty() && s != "None")
                .collect();

            // Format licenses based on output mode
            let licenses_formatted = if matches!(args.csv_output, None) {
                // Table mode: each license on new line
                if all_licenses.is_empty() {
                    "None".to_string()
                } else {
                    all_licenses.join("\n")
                }
            } else {
                // CSV mode: semicolon separation for proper CSV format
                if all_licenses.is_empty() {
                    "None".to_string()
                } else {
                    all_licenses.join("; ")
                }
            };

            CsvRecord {
                name: artifact.name.clone().unwrap_or_else(|| "Unknown".to_string()),
                version: artifact.version.clone().unwrap_or_else(|| "Unknown".to_string()),
                artifact_type: artifact.artifact_type.clone().unwrap_or_else(|| "Unknown".to_string()),
                licenses: licenses_formatted,
            }
        })
        .collect();

    // Output based on arguments
    match args.csv_output {
        Some(csv_file) => {
            // Export to CSV file
            let file = match File::create(&csv_file) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error creating CSV file {}: {}", csv_file, e);
                    process::exit(1);
                }
            };

            if let Err(e) = write_csv(file, &csv_records) {
                eprintln!("Error writing CSV: {}", e);
                process::exit(1);
            }

            println!("Successfully exported {} artifacts to {}", csv_records.len(), csv_file);
        }
        None => {
            // Print as table
            print_table(&csv_records);
        }
    }
}
