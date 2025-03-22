use std::time::Duration;
use std::thread;
use pcsc::{Context, Scope, ShareMode, Protocols, Error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TokenFlow ACR122U Test");
    println!("----------------------");
    
    // Initialize PC/SC context
    let ctx = Context::establish(Scope::User)?;
    
    // Get available readers
    let mut readers_buffer = [0; 2048]; // Buffer for reader names
    let readers = ctx.list_readers(&mut readers_buffer)?;
    
    // Check if any readers are found
    let mut found_reader = false;
    let mut acr122u = None;
    
    // Loop through readers to find ACR122U
    for reader in readers {
        let reader_name = reader.to_string_lossy();
        println!("Found reader: {}", reader_name);
        
        if reader_name.contains("ACR122") {
            acr122u = Some(reader);
            found_reader = true;
            println!("Selected ACR122U reader");
            break;
        }
    }
    
    if !found_reader {
        println!("No ACR122U reader found!");
        return Ok(());
    }
    
    let acr122u = acr122u.unwrap();
    
    println!("Waiting for cards... (place card on reader and hold it steady)");
    println!("Press Ctrl+C to quit");
    
    // Keep track of last detected UID to avoid repeats
    let mut last_uid = String::new();
    
    // Main loop
    loop {
        // Try to connect to a card
        match ctx.connect(acr122u, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                println!("Card detected! Attempting to read...");
                
                // Give the card a moment to stabilize
                thread::sleep(Duration::from_millis(100));
                
                // APDU command to get UID
                let get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00];
                
                // Prepare receive buffer
                let mut recv_buffer = [0; 256];
                
                // Transmit command
                match card.transmit(&get_uid, &mut recv_buffer) {
                    Ok(response) => {
                        if response.len() >= 2 {
                            // Check for success (ends with 9000)
                            if response[response.len()-2] == 0x90 && response[response.len()-1] == 0x00 {
                                // Extract UID (excluding status bytes)
                                let uid = &response[0..response.len()-2];
                                
                                // Format UID as hex
                                let uid_str = uid.iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect::<Vec<String>>()
                                    .join("");
                                    
                                // Only print if UID is different from last one
                                if uid_str != last_uid {
                                    println!("Card UID: {}", uid_str);
                                    println!("Token ID: ACR122-{}", uid_str);
                                    last_uid = uid_str;
                                }
                            } else {
                                println!("Error reading card. Status bytes: {:02X} {:02X}", 
                                         response[response.len()-2], 
                                         response[response.len()-1]);
                            }
                        } else {
                            println!("Invalid response length: {}", response.len());
                        }
                    },
                    Err(e) => println!("Transmit error: {}", e),
                }
                
                // Disconnect from the card properly
                match card.disconnect(pcsc::Disposition::LeaveCard) {
                    Ok(_) => {},
                    Err((_, e)) => println!("Disconnect error: {:?}", e),
                }
                
                // Wait a bit before trying again
                thread::sleep(Duration::from_millis(500));
            },
            Err(Error::NoSmartcard) => {
                // No card present, just wait
                thread::sleep(Duration::from_millis(200));
                // Clear last UID when card is removed
                if !last_uid.is_empty() {
                    println!("Card removed");
                    last_uid.clear();
                }
            },
            Err(e) => {
                // Only print error if it's not what we've seen before
                if !e.to_string().contains("Power has been removed") {
                    println!("Connect error: {}", e);
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

