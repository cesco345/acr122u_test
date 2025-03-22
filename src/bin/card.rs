use std::time::Duration;
use std::thread;
use std::error::Error;
use std::fmt;
use pcsc::{Card, Context, Scope, ShareMode, Protocols, Disposition};

// Custom error type for MIFARE operations
#[derive(Debug)]
struct MifareError {
    message: String,
    status: Option<(u8, u8)>,
}

impl MifareError {
    fn new(message: &str) -> Self {
        MifareError {
            message: message.to_string(),
            status: None,
        }
    }

    fn with_status(message: &str, status1: u8, status2: u8) -> Self {
        MifareError {
            message: message.to_string(),
            status: Some((status1, status2)),
        }
    }
}

impl fmt::Display for MifareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some((s1, s2)) => write!(f, "{}: Status {:02X} {:02X}", self.message, s1, s2),
            None => write!(f, "{}", self.message),
        }
    }
}

impl Error for MifareError {}

// Enum for key types
#[derive(Copy, Clone)]
enum KeyType {
    KeyA = 0x60,
    KeyB = 0x61,
}

// Structure to represent a MIFARE Classic card
struct MifareClassic<'a> {
    card: &'a Card,
}

impl<'a> MifareClassic<'a> {
    // Create a new MIFARE Classic handler
    fn new(card: &'a Card) -> Self {
        MifareClassic { card }
    }

    // Read UID of the card
    fn read_uid(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let get_uid = [0xFF, 0xCA, 0x00, 0x00, 0x00];
        let mut recv_buffer = [0; 256];
        
        let response = self.card.transmit(&get_uid, &mut recv_buffer)?;
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                // Extract UID (excluding status bytes)
                return Ok(response[0..response.len() - 2].to_vec());
            } else {
                return Err(Box::new(MifareError::with_status(
                    "Failed to read UID", status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when reading UID")))
    }

    // Load authentication key
    fn load_key(&self, key: &[u8]) -> Result<(), Box<dyn Error>> {
        if key.len() != 6 {
            return Err(Box::new(MifareError::new("Key must be exactly 6 bytes")));
        }
        
        let mut load_key_cmd = vec![0xFF, 0x82, 0x00, 0x00, 0x06];
        load_key_cmd.extend_from_slice(key);
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&load_key_cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(());
            } else {
                return Err(Box::new(MifareError::with_status(
                    "Failed to load key", status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when loading key")))
    }

    // Authenticate with loaded key
    fn authenticate(&self, block: u8, key_type: KeyType) -> Result<(), Box<dyn Error>> {
        let key_value = key_type as u8;
        let auth_cmd = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_value, 0x00];
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&auth_cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(());
            } else {
                return Err(Box::new(MifareError::with_status(
                    &format!("Authentication failed for block {}", block), 
                    status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length during authentication")))
    }

    // Read a block
    fn read_block(&self, block: u8) -> Result<Vec<u8>, Box<dyn Error>> {
        let read_cmd = [0xFF, 0xB0, 0x00, block, 0x10];
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&read_cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                // Extract data (excluding status bytes)
                return Ok(response[0..response.len() - 2].to_vec());
            } else {
                return Err(Box::new(MifareError::with_status(
                    &format!("Failed to read block {}", block), 
                    status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when reading block")))
    }

    // Write to a block
    fn write_block(&self, block: u8, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if data.len() != 16 {
            return Err(Box::new(MifareError::new("Data must be exactly 16 bytes")));
        }
        
        let mut write_cmd = vec![0xFF, 0xD6, 0x00, block, 0x10];
        write_cmd.extend_from_slice(data);
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&write_cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(());
            } else {
                return Err(Box::new(MifareError::with_status(
                    &format!("Failed to write to block {}", block), 
                    status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when writing block")))
    }

    // Increment a value block
    fn increment_value(&self, block: u8, value: i32) -> Result<(), Box<dyn Error>> {
        // Value blocks must be in a specific format
        let mut cmd = vec![0xFF, 0xD7, 0x00, block, 0x05, 0x01];
        
        // Convert value to bytes (little-endian)
        let value_bytes = value.to_le_bytes();
        cmd.extend_from_slice(&value_bytes);
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(());
            } else {
                return Err(Box::new(MifareError::with_status(
                    &format!("Failed to increment value block {}", block), 
                    status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when incrementing value")))
    }

    // Decrement a value block
    fn decrement_value(&self, block: u8, value: i32) -> Result<(), Box<dyn Error>> {
        let mut cmd = vec![0xFF, 0xD7, 0x00, block, 0x05, 0x02];
        
        // Convert value to bytes (little-endian)
        let value_bytes = value.to_le_bytes();
        cmd.extend_from_slice(&value_bytes);
        
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(&cmd, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(());
            } else {
                return Err(Box::new(MifareError::with_status(
                    &format!("Failed to decrement value block {}", block), 
                    status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length when decrementing value")))
    }

    // Initialize a block as value block
    fn init_value_block(&self, block: u8, value: i32) -> Result<(), Box<dyn Error>> {
        // Value block format: value (4 bytes), ~value (4 bytes), value (4 bytes), block address (1 byte), ~block address (1 byte), block address (1 byte), ~block address (1 byte)
        let mut data = [0u8; 16];
        
        // Convert value to bytes (little-endian)
        let value_bytes = value.to_le_bytes();
        
        // Set value (first 4 bytes)
        data[0..4].copy_from_slice(&value_bytes);
        
        // Set inverted value (next 4 bytes)
        let inverted_value = !value;
        let inverted_bytes = inverted_value.to_le_bytes();
        data[4..8].copy_from_slice(&inverted_bytes);
        
        // Set value again (next 4 bytes)
        data[8..12].copy_from_slice(&value_bytes);
        
        // Set block address and its complement
        data[12] = block;
        data[13] = !block;
        data[14] = block;
        data[15] = !block;
        
        // Write the value block
        self.write_block(block, &data)
    }

    // Read a value from a value block
    fn read_value(&self, block: u8) -> Result<i32, Box<dyn Error>> {
        let data = self.read_block(block)?;
        
        if data.len() < 16 {
            return Err(Box::new(MifareError::new("Invalid value block data length")));
        }
        
        // Check if this is a valid value block
        if data[0..4] != data[8..12] || data[12] != data[14] || data[13] != data[15] {
            return Err(Box::new(MifareError::new("Invalid value block format")));
        }
        
        // Convert first 4 bytes to i32 (little-endian)
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&data[0..4]);
        let value = i32::from_le_bytes(value_bytes);
        
        Ok(value)
    }

    // MIFARE direct command (for advanced operations)
    fn direct_command(&self, command: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut recv_buffer = [0; 256];
        let response = self.card.transmit(command, &mut recv_buffer)?;
        
        if response.len() >= 2 {
            let status1 = response[response.len() - 2];
            let status2 = response[response.len() - 1];
            
            if status1 == 0x90 && status2 == 0x00 {
                return Ok(response[0..response.len() - 2].to_vec());
            } else {
                return Err(Box::new(MifareError::with_status(
                    "Direct command failed", status1, status2
                )));
            }
        }
        
        Err(Box::new(MifareError::new("Invalid response length for direct command")))
    }
}

// Helper function to format bytes as hex string
fn format_hex(bytes: &[u8]) -> String {
    bytes.iter()
         .map(|b| format!("{:02X}", b))
         .collect::<Vec<String>>()
         .join("")
}

// Helper function to print block data
fn print_block_data(block_num: u8, data: &[u8]) {
    println!("Block {:02}: {:?}", block_num, format_hex(data));
    
    println!("       : ASCII: {}", data.iter()
        .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
        .collect::<String>());
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("MIFARE Classic Card Operations");
    println!("-----------------------------");
    
    // Initialize PC/SC context
    let ctx = Context::establish(Scope::User)?;
    
    // Get available readers
    let mut readers_buffer = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buffer)?;
    
    // Find ACR122U reader
    let mut acr122u = None;
    
    for reader in readers {
        let reader_name = reader.to_string_lossy();
        println!("Found reader: {}", reader_name);
        
        if reader_name.contains("ACR122") {
            acr122u = Some(reader);
            println!("Selected ACR122U reader");
            break;
        }
    }
    
    let acr122u = match acr122u {
        Some(reader) => reader,
        None => {
            println!("No ACR122U reader found!");
            return Ok(());
        }
    };
    
    println!("Waiting for card... (place card on reader)");
    println!("Press Ctrl+C to quit");
    
    // Default MIFARE keys to try
    let default_keys = [
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Factory default
        [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], // Common alternative
        [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], // Another common key
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // All zeros
    ];
    
    // Main loop
    loop {
        // Try to connect to a card
        match ctx.connect(acr122u, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                println!("\nCard detected!");
                
                // Give the card a moment to stabilize
                thread::sleep(Duration::from_millis(100));
                
                // Create MIFARE handler
                let mifare = MifareClassic::new(&card);
                
                // Read and display card UID
                match mifare.read_uid() {
                    Ok(uid) => {
                        println!("Card UID: {}", format_hex(&uid));
                        
                        // Menu loop for operations
                        'menu: loop {
                            println!("\nChoose an operation:");
                            println!("1. Read a block");
                            println!("2. Write to a block");
                            println!("3. Initialize a value block");
                            println!("4. Increment a value block");
                            println!("5. Decrement a value block");
                            println!("6. Read a value block");
                            println!("7. Dump all accessible blocks");
                            println!("8. Exit");
                            
                            // For simplicity in this example, we'll use a fixed choice
                            // In a real application, you'd read user input
                            let choice = 7; // Dump all blocks
                            
                            match choice {
                                1 => {
                                    // Read a block
                                    let block = 4; // Example: block 4
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.read_block(block) {
                                            Ok(data) => {
                                                print_block_data(block, &data);
                                            },
                                            Err(e) => println!("Error reading block: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                2 => {
                                    // Write to a block
                                    let block = 4; // Example: block 4
                                    let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.write_block(block, &data) {
                                            Ok(()) => {
                                                println!("Successfully wrote to block {}", block);
                                                println!("Data: {}", format_hex(&data));
                                            },
                                            Err(e) => println!("Error writing to block: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                3 => {
                                    // Initialize a value block
                                    let block = 4; // Example: block 4
                                    let value = 100; // Initial value
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.init_value_block(block, value) {
                                            Ok(()) => {
                                                println!("Successfully initialized value block {} with value {}", block, value);
                                            },
                                            Err(e) => println!("Error initializing value block: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                4 => {
                                    // Increment a value block
                                    let block = 4; // Example: block 4
                                    let increment = 10; // Amount to increment
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.increment_value(block, increment) {
                                            Ok(()) => {
                                                println!("Successfully incremented value block {} by {}", block, increment);
                                            },
                                            Err(e) => println!("Error incrementing value: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                5 => {
                                    // Decrement a value block
                                    let block = 4; // Example: block 4
                                    let decrement = 5; // Amount to decrement
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.decrement_value(block, decrement) {
                                            Ok(()) => {
                                                println!("Successfully decremented value block {} by {}", block, decrement);
                                            },
                                            Err(e) => println!("Error decrementing value: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                6 => {
                                    // Read a value block
                                    let block = 4; // Example: block 4
                                    
                                    // Try to authenticate with default keys
                                    let mut authenticated = false;
                                    for key in &default_keys {
                                        if let Ok(()) = mifare.load_key(key) {
                                            if let Ok(()) = mifare.authenticate(block, KeyType::KeyA) {
                                                authenticated = true;
                                                println!("Authenticated with key: {}", format_hex(key));
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if authenticated {
                                        match mifare.read_value(block) {
                                            Ok(value) => {
                                                println!("Value block {} contains: {}", block, value);
                                            },
                                            Err(e) => println!("Error reading value: {}", e),
                                        }
                                    } else {
                                        println!("Failed to authenticate with any key");
                                    }
                                },
                                7 => {
                                    // Dump all accessible blocks
                                    println!("\nDumping all accessible blocks:");
                                    
                                    // For a 1K card, try all blocks
                                    for sector in 0..16 {
                                        println!("\nSector {}:", sector);
                                        
                                        let first_block = sector * 4;
                                        let is_first_sector = sector == 0;
                                        
                                        // Try both key types
                                        for key_type in [KeyType::KeyA, KeyType::KeyB] {
                                            let key_name = match key_type {
                                                KeyType::KeyA => "A",
                                                KeyType::KeyB => "B",
                                            };
                                            
                                            // Try all default keys
                                            for key in &default_keys {
                                                if let Ok(()) = mifare.load_key(key) {
                                                    // Authenticate with sector's first block
                                                    if let Ok(()) = mifare.authenticate(first_block, key_type) {
                                                        println!("  Authenticated sector {} with Key {}: {}", 
                                                                sector, key_name, format_hex(key));
                                                        
                                                        // Read all blocks in the sector
                                                        for i in 0..4 {
                                                            let block = first_block + i;
                                                            
                                                            // Skip block 0 (manufacturer data) to avoid potential issues
                                                            if is_first_sector && i == 0 {
                                                                println!("  Block 00: Manufacturer data (skipped)");
                                                                continue;
                                                            }
                                                            
                                                            match mifare.read_block(block) {
                                                                Ok(data) => {
                                                                    print!("  ");
                                                                    print_block_data(block, &data);
                                                                },
                                                                Err(e) => {
                                                                    println!("  Block {:02}: Error reading: {}", block, e);
                                                                }
                                                            }
                                                        }
                                                        
                                                        // If we authenticated with this key, no need to try others
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    
                                    println!("\nDump complete.");
                                },
                                8 => {
                                    println!("Exiting menu...");
                                    break 'menu;
                                },
                                _ => println!("Invalid choice!"),
                            }
                            
                            // Exit the menu after performing the operation
                            break 'menu;
                        }
                    },
                    Err(e) => println!("Error reading UID: {}", e),
                }
                
                // Disconnect from the card properly
                let _ = card.disconnect(Disposition::LeaveCard);
                
                // Wait a bit before trying to connect again
                thread::sleep(Duration::from_millis(1000));
            },
            Err(pcsc::Error::NoSmartcard) => {
                // No card present, just wait
                thread::sleep(Duration::from_millis(200));
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
