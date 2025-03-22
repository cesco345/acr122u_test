# MIFARE Classic Card Operations with ACR122U

This guide provides step-by-step instructions for setting up and using an ACR122U RFID/NFC reader with a Raspberry Pi to read and write MIFARE Classic cards.

## Hardware Requirements

- Raspberry Pi (any model with USB ports)
- ACR122U RFID/NFC reader
- MIFARE Classic 1K cards

## 1. Initial Raspberry Pi Setup

### 1.1 Start with a fresh Raspberry Pi OS

If you don't have Raspberry Pi OS installed:
1. Download and flash [Raspberry Pi OS](https://www.raspberrypi.org/software/) to an SD card
2. Insert the SD card into your Raspberry Pi and connect power, monitor, keyboard, and mouse
3. Complete the initial setup process

### 1.2 Update your system

```bash
sudo apt-get update
sudo apt-get upgrade -y
```

## 2. Setting up the ACR122U Reader

### 2.1 Install necessary libraries

```bash
sudo apt-get install pcscd pcsc-tools libccid -y
```

### 2.2 Connect the ACR122U Reader

1. Plug the ACR122U reader into an available USB port on your Raspberry Pi
2. Wait a few seconds for the device to be recognized

### 2.3 Create udev rules for the ACR122U

```bash
sudo nano /etc/udev/rules.d/92-acr122.rules
```

Add the following content:
```
# ACR122U reader
SUBSYSTEM=="usb", ATTRS{idVendor}=="072f", ATTRS{idProduct}=="2200", GROUP="plugdev", MODE="0660"
```

### 2.4 Reload udev rules and restart services

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo systemctl restart pcscd
```

### 2.5 Verify the reader is working

```bash
pcsc_scan
```

This should show the ACR122U reader. If you place a card on the reader, it should detect it and display information about the card.

## 3. Setting up the Rust Environment

### 3.1 Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts to complete the installation, usually selecting option 1 for default installation.

### 3.2 Apply the Rust environment to your current shell

```bash
source $HOME/.cargo/env
```

### 3.3 Install dependencies for the PCSC Rust library

```bash
sudo apt-get install libpcsclite-dev -y
```

## 4. Creating the MIFARE Classic Card Project

### 4.1 Create a new Rust project

```bash
mkdir -p ~/rust/acr122u_test
cd ~/rust/acr122u_test
cargo init
```

### 4.2 Set up the project dependencies

Edit `Cargo.toml`:
```bash
nano Cargo.toml
```

Add the following:
```toml
[dependencies]
pcsc = "2.5.0"
```

### 4.3 Create a directory for the card application

```bash
mkdir -p src/bin
```

### 4.4 Create the MIFARE Classic card application

```bash
nano src/bin/card.rs
```

Paste the complete code from the artifact provided above into this file.

## 5. Build and Run the Application

### 5.1 Build the application

```bash
cargo build
```

### 5.2 Run the application

```bash
cargo run --bin card
```

## 6. Using the Application

When you run the application:

1. It will detect and connect to the ACR122U reader
2. Wait for you to place a MIFARE Classic card on the reader
3. Read the card's UID
4. Present a menu of operations (for the example code, it will automatically choose option 7 to dump all blocks)
5. Try to authenticate each sector with multiple common keys
6. Read and display all blocks it can access

### 6.1 Troubleshooting Card Access

If the application can't read your card's data blocks, this is likely because your card is using different keys than the default ones provided. Options include:

1. Adding your known keys to the `default_keys` array
2. Using key recovery tools like MFOC (requires separate installation)
3. For some cards (like public transit cards), the keys may be proprietary and not easily accessible

### 6.2 Understanding MIFARE Classic Card Structure

MIFARE Classic 1K cards:
- Have 16 sectors (numbered 0-15)
- Each sector has 4 blocks (so 64 blocks total, numbered 0-63)
- The last block of each sector (blocks 3, 7, 11, etc.) is a "sector trailer" containing keys and access bits
- Block 0 contains manufacturer data and should not be modified

## 7. Customizing the Application

To customize the application for your needs:

1. Modify the menu system to accept user input instead of using a fixed choice
2. Add your own card-specific keys to the `default_keys` array
3. Implement additional MIFARE commands for specialized operations
4. Add error handling and recovery for failed operations

## 8. Common Issues and Solutions

### Reader not detected

```bash
sudo systemctl restart pcscd
pcsc_scan
```

If pcsc_scan doesn't show the reader, check:
- USB connections
- Try a different USB port
- Verify the reader has power (LED should be on)

### "Connection timed out" errors

This can happen when multiple processes try to access the reader:
```bash
sudo systemctl stop pcscd
sudo systemctl start pcscd
```

### Card not reading correctly

- Ensure the card is properly positioned on the reader
- Try holding the card steady for a few seconds
- Some cards may need to be placed at specific positions on the reader

## 9. Advanced Usage

### 9.1 Adding Custom Keys

To add custom keys, modify the `default_keys` array in the code:

```rust
let default_keys = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Factory default
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], // Common alternative
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], // Another common key
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // All zeros
    // Add your custom keys here
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], // Custom key example
];
```

### 9.2 Working with Value Blocks

MIFARE Classic cards support "value blocks" that include built-in increment/decrement operations:

1. Initialize a block as a value block:
   ```
   mifare.init_value_block(block_number, initial_value)
   ```

2. Increment the value:
   ```
   mifare.increment_value(block_number, amount)
   ```

3. Decrement the value:
   ```
   mifare.decrement_value(block_number, amount)
   ```

4. Read the current value:
   ```
   mifare.read_value(block_number)
   ```

## Resources

- [ACR122U Documentation](https://www.acs.com.hk/en/products/3/acr122u-usb-nfc-reader/)
- [MIFARE Classic Documentation](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)
- [PC/SC Workgroup](https://pcscworkgroup.com/)
- [Rust pcsc crate documentation](https://docs.rs/pcsc/latest/pcsc/)

## Command Reference

### Key Loading and Authentication

```bash
# Load the default key
opensc-tool --reader 0 --send-apdu FF:82:00:00:06:00:00:00:00:00:00

# Authenticate sector 1 (which contains block 5)
opensc-tool --reader 0 --send-apdu FF:86:00:00:05:01:00:04:60:00
```

### Writing and Reading Data

```bash
# Write your message to block 5
opensc-tool --reader 0 --send-apdu FF:D6:00:05:10:48:65:6C:6C:6F:20:59:6F:75:54:75:62:65:21:21:21

# Authenticate sector 1 if needed
opensc-tool --reader 0 --send-apdu FF:86:00:00:05:01:00:04:60:00

# Read block 5
opensc-tool --reader 0 --send-apdu FF:B0:00:05:10
```

### Reading Sector 0

```bash
# Authenticate Sector 0 with Key A
opensc-tool --reader 0 --send-apdu FF:86:00:00:05:01:00:00:60:00

# Read Block 0 (Manufacturer Block with UID)
opensc-tool --reader 0 --send-apdu FF:B0:00:00:10

# Read Block 1 (Data)
opensc-tool --reader 0 --send-apdu FF:B0:00:01:10

# Read Block 2 (Data)
opensc-tool --reader 0 --send-apdu FF:B0:00:02:10

# Read Block 3 (Sector 0 Trailer with Keys)
opensc-tool --reader 0 --send-apdu FF:B0:00:03:10
```

### Reading Sector 1

```bash
# Authenticate Sector 1 with Key A
opensc-tool --reader 0 --send-apdu FF:86:00:00:05:01:00:04:60:00

# Read Block 4
opensc-tool --reader 0 --send-apdu FF:B0:00:04:10

# Read Block 5
opensc-tool --reader 0 --send-apdu FF:B0:00:05:10

# Read Block 6
opensc-tool --reader 0 --send-apdu FF:B0:00:06:10

# Read Block 7 (Sector 1 Trailer)
opensc-tool --reader 0 --send-apdu FF:B0:00:07:10
```

## Bash Script to Read All Sectors

```bash
#!/bin/bash

# Load the default key
opensc-tool --reader 0 --send-apdu FF:82:00:00:06:FF:FF:FF:FF:FF:FF

# Loop through all sectors
for sector in {0..15}
do
    echo "Reading Sector $sector:"

    # Calculate the first block in this sector
    first_block=$((sector * 4))

    # Authenticate with Key A
    echo " Authenticating..."
    opensc-tool --reader 0 --send-apdu FF:86:00:00:05:01:00:$(printf "%02x" $first_block):60:00

    # Read all 4 blocks in this sector
    for offset in {0..3}
    do
        block=$((first_block + offset))
        echo " Reading Block $block:"
        opensc-tool --reader 0 --send-apdu FF:B0:00:$(printf "%02x" $block):10
    done
    echo ""
done
```

## Device Information

```bash
lsusb
# Output: Bus 001 Device 004: ID 072f:2200 Advanced Card Systems, Ltd ACR122U

# Install required packages
sudo apt-get update
sudo apt-get install -y pcscd pcsc-tools libpcsclite-dev libusb-dev libccid

# Restart the PC/SC daemon and scan for readers
sudo systemctl restart pcscd
pcsc_scan
# Output: PC/SC device scanner
#         Waiting for the first reader...
#         Reader: ACS ACR122U PICC Interface 00 00
```

## Project Setup

```bash
# On the Raspberry Pi
mkdir acr122u_test
cd acr122u_test
cargo init

# Edit Cargo.toml to add dependencies
nano Cargo.toml
```

Add the following to your Cargo.toml:

```toml
[dependencies]
pcsc = "2.4"
```
