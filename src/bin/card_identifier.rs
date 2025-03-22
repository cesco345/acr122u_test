use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use regex::Regex;

// Main struct to hold card information
struct CardInfo {
    atr: String,
    description: Vec<String>,
    card_type: MifareType,
}

// Enum for different Mifare card types
#[derive(Debug, Clone, PartialEq)]
enum MifareType {
    MifareClassic1K,
    MifareClassic4K,
    MifareMini,
    MifareUltralight,
    MifareDesfire,
    MifarePlus,
    OtherMifare,
    Unknown,
}

impl MifareType {
    fn to_string(&self) -> &str {
        match self {
            MifareType::MifareClassic1K => "Mifare Classic 1K",
            MifareType::MifareClassic4K => "Mifare Classic 4K",
            MifareType::MifareMini => "Mifare Mini",
            MifareType::MifareUltralight => "Mifare Ultralight",
            MifareType::MifareDesfire => "Mifare DESFire",
            MifareType::MifarePlus => "Mifare Plus",
            MifareType::OtherMifare => "Other Mifare Type",
            MifareType::Unknown => "Unknown Card Type",
        }
    }
}

// Function to parse the smartcard list file and build a database of ATRs
fn build_atr_database(file_path: &str) -> Result<HashMap<String, CardInfo>, io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut database = HashMap::new();
    
    let mut current_atr = String::new();
    let mut current_descriptions = Vec::new();
    let mut line_count = 0;
    let mut atr_count = 0;
    
    println!("Parsing smartcard database file...");
    
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        line_count += 1;
        
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        
        // If line has ATR format (starts with 3B or 3F)
        if trimmed.starts_with("3B") || trimmed.starts_with("3F") {
            // If we have a previous ATR, save it before starting a new one
            if !current_atr.is_empty() && !current_descriptions.is_empty() {
                let card_type = identify_card_type(&current_atr, &current_descriptions);
                database.insert(current_atr.clone(), CardInfo {
                    atr: current_atr.clone(),
                    description: current_descriptions.clone(),
                    card_type,
                });
                atr_count += 1;
            }
            
            // Start new ATR
            current_atr = trimmed.to_string();
            current_descriptions = Vec::new();
        } else if trimmed.starts_with('\t') || (!trimmed.starts_with("3B") && !trimmed.starts_with("3F") && !current_atr.is_empty()) {
            // This is a description line - note we're being more lenient about format
            current_descriptions.push(trimmed.trim().to_string());
        }
    }
    
    // Don't forget to add the last entry
    if !current_atr.is_empty() && !current_descriptions.is_empty() {
        let card_type = identify_card_type(&current_atr, &current_descriptions);
        database.insert(current_atr.clone(), CardInfo {
            atr: current_atr,
            description: current_descriptions,
            card_type,
        });
        atr_count += 1;
    }
    
    println!("Processed {} lines, found {} ATR entries", line_count, atr_count);
    
    if database.is_empty() {
        println!("Warning: No ATR entries found in the file. Check file format.");
        println!("File should contain lines starting with '3B' or '3F' for ATRs");
        println!("followed by indented description lines.");
    }
    
    Ok(database)
}

// Function to identify the card type based on ATR and descriptions
fn identify_card_type(atr: &str, descriptions: &[String]) -> MifareType {
    // Check if any description contains Mifare keywords
    let desc_text = descriptions.join(" ").to_lowercase();
    
    // Specific ATR patterns for common Mifare cards
    if atr.contains("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01") {
        return MifareType::MifareClassic1K;
    } else if atr.contains("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 02") {
        return MifareType::MifareClassic4K;
    } else if atr.contains("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03") {
        return MifareType::MifareUltralight;
    } else if atr.contains("3B 8F 80 01 80 4F 0C A0 00 00 03 06 00 26") {
        return MifareType::MifareMini;
    } else if atr.contains("3B 81 80 01 80 80") || desc_text.contains("desfire") {
        return MifareType::MifareDesfire;
    } else if desc_text.contains("mifare plus") {
        return MifareType::MifarePlus;
    } 
    
    // Check in descriptions
    if desc_text.contains("mifare") {
        if desc_text.contains("1k") || desc_text.contains("classic") && !desc_text.contains("4k") {
            return MifareType::MifareClassic1K;
        } else if desc_text.contains("4k") {
            return MifareType::MifareClassic4K;
        } else if desc_text.contains("mini") {
            return MifareType::MifareMini;
        } else if desc_text.contains("ultralight") {
            return MifareType::MifareUltralight;
        } else if desc_text.contains("desfire") {
            return MifareType::MifareDesfire;
        } else if desc_text.contains("plus") {
            return MifareType::MifarePlus;
        } else {
            return MifareType::OtherMifare;
        }
    }
    
    MifareType::Unknown
}

// Function to read ATR from an ACR122U reader
fn read_atr_from_acr122u() -> Result<String, String> {
    // First check if PC/SC daemon is running
    let pcscd_status = Command::new("systemctl")
        .args(["is-active", "pcscd"])
        .output()
        .map_err(|e| format!("Failed to check pcscd status: {}", e))?;
    
    let pcscd_active = String::from_utf8_lossy(&pcscd_status.stdout).trim() == "active";
    
    if !pcscd_active {
        println!("Warning: pcscd service is not running. Attempting to start it...");
        let _ = Command::new("sudo")
            .args(["systemctl", "start", "pcscd"])
            .output();
        
        println!("Waiting 3 seconds for pcscd to start...");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    
    // Try nfc-list first as it's more reliable with ACR122U
    println!("Trying nfc-list to detect card...");
    let nfc_output = Command::new("nfc-list")
        .output();
    
    if let Ok(output) = nfc_output {
        let output_text = String::from_utf8_lossy(&output.stdout);
        println!("nfc-list output: {}", output_text);
        
        // Extract UID and try to determine card type from nfc-list output
        if output_text.contains("UID") {
            // This is a fallback since we couldn't get the real ATR
            // We'll create a synthetic ATR based on what we know
            if output_text.contains("MIFARE Classic") || output_text.contains("MIFARE 1k") {
                return Ok("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 00".to_string());
            } else if output_text.contains("MIFARE 4k") {
                return Ok("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 02 00 00 00 00 00".to_string());
            } else if output_text.contains("Ultralight") || output_text.contains("NTAG") {
                return Ok("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00 00".to_string());
            } else if output_text.contains("DESFire") {
                return Ok("3B 81 80 01 80 80".to_string());
            } else {
                println!("Card detected but type not recognized from nfc-list");
                // Return a generic Mifare card ATR
                return Ok("3B 8F 80 01 80 4F 0C A0 00 00 03 06 00 00 00 00 00 00 00 00".to_string());
            }
        }
    } else {
        println!("nfc-list command failed, falling back to pcsc_scan");
    }
    
    // Fall back to pcsc_scan
    println!("Using pcsc_scan to detect card...");
    let output = Command::new("pcsc_scan")
        .args(["-r"])  // Run once
        .output()
        .map_err(|e| format!("Failed to execute pcsc_scan: {}", e))?;
    
    let output_text = String::from_utf8_lossy(&output.stdout);
    println!("pcsc_scan output: {}", output_text);
    
    // Use regex to extract the ATR from pcsc_scan output
    let re = Regex::new(r"ATR: ([0-9A-F ]+)").unwrap();
    if let Some(captures) = re.captures(&output_text) {
        if let Some(atr_match) = captures.get(1) {
            return Ok(atr_match.as_str().to_string());
        }
    }
    
    // Alternative: try to use pcsc_tools' scriptor or pcsc-lite directly
    println!("No card detected. Please ensure the card is placed properly on the reader.");
    
    Err("Could not find ATR or detect card. Is a card present on the reader?".to_string())
}

// Function to determine the authentication methods available for the identified card type
fn get_authentication_methods(card_type: &MifareType) -> Vec<String> {
    match card_type {
        MifareType::MifareClassic1K | MifareType::MifareClassic4K => {
            vec![
                "Type A authentication".to_string(),
                "3-Pass Authentication (ISO 9798-2)".to_string(),
                "CRYPTO1 cipher (proprietary)".to_string(),
                "Note: Classic encryption has been broken and is not secure".to_string(),
            ]
        },
        MifareType::MifareMini => {
            vec![
                "Type A authentication".to_string(),
                "CRYPTO1 cipher (proprietary)".to_string(),
                "Same security as Mifare Classic but less memory".to_string(),
            ]
        },
        MifareType::MifareUltralight => {
            vec![
                "No cryptographic protection in basic version".to_string(),
                "Ultralight C adds 3DES authentication".to_string(),
                "Mainly relies on limited access facility".to_string(),
            ]
        },
        MifareType::MifareDesfire => {
            vec![
                "DESFire EV1: 3DES and AES (128-bit) encryption".to_string(),
                "DESFire EV2/EV3: AES (128-bit) encryption".to_string(),
                "Supports ISO/IEC 7816-4 command set".to_string(),
                "Multiple applications with diverse keys".to_string(),
                "Mutual three-pass authentication".to_string(),
            ]
        },
        MifareType::MifarePlus => {
            vec![
                "Supports AES 128-bit encryption".to_string(),
                "Backwards compatibility with CRYPTO1".to_string(),
                "Multiple security levels (SL0-SL3)".to_string(),
                "Enhanced key management features".to_string(),
            ]
        },
        MifareType::OtherMifare => {
            vec![
                "Authentication method depends on specific Mifare variant".to_string(),
                "Please consult the specific card documentation".to_string(),
            ]
        },
        MifareType::Unknown => {
            vec![
                "Unknown card type, cannot determine authentication methods".to_string(),
                "Try manual identification or contact card manufacturer".to_string(),
            ]
        },
    }
}

// Main function that brings everything together
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Mifare Card Identifier for ACR122U");
    println!("==================================\n");
    
    // Check if required tools are available
    check_prerequisites();
    
    // Build the database from the smartcard list file
    let database_path = "smartcard_list.txt";
    println!("Building ATR database from {}...", database_path);
    
    let database = match build_atr_database(database_path) {
        Ok(db) => {
            println!("Successfully loaded {} ATR records", db.len());
            db
        },
        Err(e) => {
            println!("Warning: Could not load ATR database: {}", e);
            println!("Continuing with limited identification capabilities...");
            HashMap::new()
        }
    };
    
    println!("\nLooking for ACR122U reader and card...");
    
    // Try to read the ATR from the card
    let atr = match read_atr_from_acr122u() {
        Ok(atr) => {
            println!("Successfully read card ATR: {}", atr);
            atr
        },
        Err(e) => {
            println!("Error reading card: {}", e);
            println!("Please make sure your ACR122U reader is connected and a card is present.");
            
            // If no card was detected, offer manual card type selection
            println!("\nWould you like to manually specify the card type? (y/n)");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            
            if input.trim().to_lowercase() == "y" {
                let card_type = manual_card_selection()?;
                
                // Display authentication methods for manually selected card
                println!("\nAuthentication Methods for {}:", card_type.to_string());
                for method in get_authentication_methods(&card_type) {
                    println!("  - {}", method);
                }
                
                // Provide usage recommendations
                print_usage_recommendations(&card_type);
                
                return Ok(());
            } else {
                return Ok(());
            }
        }
    };
    
    // Normalize ATR by removing spaces for lookup
    let normalized_atr = atr.replace(" ", "");
    
    // Look up the ATR in our database
    let mut found = false;
    let mut identified_card_type = MifareType::Unknown;
    
    for (db_atr, card_info) in &database {
        let normalized_db_atr = db_atr.replace(" ", "");
        
        // Also try with wildcard pattern matching for flexible ATR matching
        if normalized_atr == normalized_db_atr || atr_pattern_match(&normalized_atr, &normalized_db_atr) {
            found = true;
            identified_card_type = card_info.card_type.clone();
            
            println!("\nCard Identified:");
            println!("  Type: {}", card_info.card_type.to_string());
            println!("  ATR: {}", card_info.atr);
            println!("  Descriptions:");
            for desc in &card_info.description {
                println!("    - {}", desc);
            }
            break;
        }
    }
    
    // If the card is not found in the database, try to identify by ATR pattern
    if !found {
        println!("\nCard not found in database. Attempting pattern-based identification...");
        identified_card_type = identify_by_atr_pattern(&atr);
        println!("  Identified as: {}", identified_card_type.to_string());
    }
    
    // Display authentication methods
    println!("\nAuthentication Methods for {}:", identified_card_type.to_string());
    for method in get_authentication_methods(&identified_card_type) {
        println!("  - {}", method);
    }
    
    // Provide usage recommendations
    print_usage_recommendations(&identified_card_type);
    
    println!("\nMifare Card Identification Complete");
    
    Ok(())
}

// Function to check if required tools are installed
fn check_prerequisites() {
    println!("Checking for required tools...");
    
    // Check for pcsc_scan
    let pcsc_scan_check = Command::new("which")
        .arg("pcsc_scan")
        .output();
    
    match pcsc_scan_check {
        Ok(output) => {
            if output.status.success() {
                println!("✓ pcsc_scan found");
            } else {
                println!("✗ pcsc_scan not found. Install with 'sudo apt-get install pcsc-tools'");
            }
        },
        Err(_) => println!("✗ pcsc_scan not found. Install with 'sudo apt-get install pcsc-tools'"),
    }
    
    // Check for nfc-list
    let nfc_list_check = Command::new("which")
        .arg("nfc-list")
        .output();
    
    match nfc_list_check {
        Ok(output) => {
            if output.status.success() {
                println!("✓ nfc-list found");
            } else {
                println!("✗ nfc-list not found. Install with 'sudo apt-get install libnfc-bin'");
            }
        },
        Err(_) => println!("✗ nfc-list not found. Install with 'sudo apt-get install libnfc-bin'"),
    }
    
    // Check if pcscd service is running
    let pcscd_check = Command::new("systemctl")
        .args(["is-active", "pcscd"])
        .output();
    
    match pcscd_check {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if status == "active" {
                println!("✓ pcscd service is running");
            } else {
                println!("✗ pcscd service is not running. Start with 'sudo systemctl start pcscd'");
            }
        },
        Err(_) => println!("✗ Could not check pcscd service status"),
    }
    
    println!("");
}

// Function for manual card type selection
fn manual_card_selection() -> Result<MifareType, Box<dyn std::error::Error>> {
    println!("\nPlease select your card type:");
    println!("1. Mifare Classic 1K");
    println!("2. Mifare Classic 4K");
    println!("3. Mifare Mini");
    println!("4. Mifare Ultralight");
    println!("5. Mifare DESFire");
    println!("6. Mifare Plus");
    println!("7. Other Mifare Type");
    println!("8. Unknown Card Type");
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let selection = input.trim().parse::<u8>().unwrap_or(8);
    
    let card_type = match selection {
        1 => MifareType::MifareClassic1K,
        2 => MifareType::MifareClassic4K,
        3 => MifareType::MifareMini,
        4 => MifareType::MifareUltralight,
        5 => MifareType::MifareDesfire,
        6 => MifareType::MifarePlus,
        7 => MifareType::OtherMifare,
        _ => MifareType::Unknown,
    };
    
    println!("Selected card type: {}", card_type.to_string());
    
    Ok(card_type)
}

// Separate function for usage recommendations
fn print_usage_recommendations(identified_card_type: &MifareType) {
    println!("\nRecommended Usage:");
    match identified_card_type {
        MifareType::MifareClassic1K | MifareType::MifareClassic4K => {
            println!("  - For this card, use libnfc with mfoc or mfcuk tools for authentication");
            println!("  - Basic command: 'nfc-list' to detect the card");
            println!("  - Authentication command: 'mfoc -O dump.mfd' to dump the card contents");
            println!("  - Install required tools: 'sudo apt-get install libnfc-bin mfoc'");
        },
        MifareType::MifareUltralight => {
            println!("  - For Ultralight cards, use nfc-mfultralight tool");
            println!("  - Command: 'nfc-mfultralight r dump.mfd' to read the card");
            println!("  - Install required tools: 'sudo apt-get install libnfc-bin'");
        },
        MifareType::MifareDesfire => {
            println!("  - Use mifare-desfire-tool or official NXP libraries");
            println!("  - Requires proper key management and authentication procedures");
            println!("  - Consider installing: 'sudo apt-get install libfreefare-bin'");
        },
        MifareType::MifarePlus => {
            println!("  - Depending on security level, use appropriate AES libraries");
            println!("  - Consider using official SDK for secure implementation");
            println!("  - In security level 1, can be accessed like Mifare Classic");
        },
        _ => {
            println!("  - For this card type, consult specific documentation");
            println!("  - Start with 'pcsc_scan' and 'pcsc_tools' for basic interaction");
            println!("  - Try 'sudo apt-get install pcsc-tools libnfc-bin libfreefare-bin'");
        }
    }
}

// Function to match ATR patterns with wildcards
fn atr_pattern_match(actual_atr: &str, pattern_atr: &str) -> bool {
    let pattern_bytes: Vec<&str> = pattern_atr
        .split("")
        .filter(|s| !s.is_empty())
        .collect();
    
    let actual_bytes: Vec<&str> = actual_atr
        .split("")
        .filter(|s| !s.is_empty())
        .collect();
    
    if actual_bytes.len() != pattern_bytes.len() {
        return false;
    }
    
    for (i, &pattern_char) in pattern_bytes.iter().enumerate() {
        if pattern_char != "." && pattern_char != actual_bytes[i] {
            return false;
        }
    }
    
    true
}

// Function to identify card type based on ATR pattern when not found in database
fn identify_by_atr_pattern(atr: &str) -> MifareType {
    // Common patterns for Mifare cards
    if atr.contains("3B 8F 80 01 80 4F") || atr.contains("3B8F80018F4F") {
        // This is a PCSC standard for contactless cards
        if atr.contains("00 01") || atr.contains("0001") {
            return MifareType::MifareClassic1K;
        } else if atr.contains("00 02") || atr.contains("0002") {
            return MifareType::MifareClassic4K;
        } else if atr.contains("00 03") || atr.contains("0003") {
            return MifareType::MifareUltralight;
        } else if atr.contains("00 26") || atr.contains("0026") {
            return MifareType::MifareMini;
        }
    }
    
    // DESFire pattern
    if atr.contains("3B 81 80") || atr.contains("3B8180") {
        return MifareType::MifareDesfire;
    }
    
    // Check for Mifare Plus indicators
    if atr.contains("3B 8F") && (atr.contains("PLUS") || atr.contains("plus")) {
        return MifareType::MifarePlus;
    }
    
    // General Mifare pattern
    if atr.contains("3B") && atr.contains("80") {
        return MifareType::OtherMifare;
    }
    
    MifareType::Unknown
}
