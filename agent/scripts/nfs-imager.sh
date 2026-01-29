#!/bin/bash
# acquirepi - Forensic Imager for Raspberry Pi
# Copyright (C) 2024 plonxyz
# https://github.com/plonxyz/acquirepi
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Configuration
GPIO_PIN_LED=5
GPIO_PIN_OK=6
LED_PATH="/sys/class/leds/ACT/brightness"
LOGFILE="/var/log/acquire.log"
# SATA HAT paths (supports 2 SATA devices via PCIe SATA controller)
SATA_PORT1_PATH_TAG="platform-1000110000_pcie-pci-0000_03_00_0-ata-1_0"
SATA_PORT2_PATH_TAG="platform-1000110000_pcie-pci-0000_03_00_0-ata-2_0"
# NVMe HAT path (single NVMe device via PCIe)
NVME_PATH_TAG="platform-1000110000_pcie-pci-0000_04_00_0-nvme-1"
# Legacy USB paths (kept for backwards compatibility)
USBPORT1_PATH_TAG_USB2="platform-xhci-hcd_1-usb-0_1_3_1_0-scsi-0_0_0_0"
USBPORT1_PATH_TAG_USB3="platform-xhci-hcd_1-usb-0_1_1_0-scsi-0_0_0_0"
SEGMENT_SIZE="2199023255552"

# Create log file and set permissions


# Functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $RUN_ID - $1" >> "$LOGFILE" 2>&1
}

led_control() {
    echo "$1" | sudo tee $LED_PATH > /dev/null
}

get_block_device_path() {
    # Takes multiple path tags as arguments and returns first matching device
    for device in $(lsblk -lno NAME,TYPE | grep -E "\<disk\>" | awk '{print $1}'); do
        # Skip the boot device (mmcblk0)
        if [[ "$device" == "mmcblk0" ]]; then
            continue
        fi

        local udev_info=$(udevadm info --query=all --name="/dev/$device")

        # Check if device matches any of the provided path tags
        for path_tag in "$@"; do
            if echo "$udev_info" | grep -q "ID_PATH_TAG=$path_tag"; then
                echo "/dev/$device"
                return
            fi
        done
    done
}

blink_led() {
    local interval=$1
    while true; do
        led_control 1
        # gpio disabled
        sleep $interval
        led_control 0
        # gpio disabled
        sleep $interval
    done
}

static_led_ok() {
    # gpio disabled
    led_control 1
}
lcd_write() {
    if [ -x "$LCD_WRITE_SCRIPT" ]; then
        $LCD_WRITE_SCRIPT "$1" "$2" > /dev/null 2>&1
    else
        echo "LCD message (not displayed): $1"
    fi
}
update_lcd() {
    local acquired_gb=$1
    local total_gb=$2
    local speed=$3

    lcd_write "$(printf "ACQUIRE NFS-MODE \n %5s/%5s %7s" "${acquired_gb}" "${total_gb}" "${speed}")"
}

get_yaml_value() {
    local key=$1
    local value

    # Try the new structure first
    value=$(yq e ".system.$key" "$YAML_FILE")
    
    # If empty, try the old structure
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        value=$(yq e ".$key" "$YAML_FILE")
    fi

    echo "$value"
}

mount_nfs() {
    local nfs_server=$(get_yaml_value "system.nfs-config.server")
    local nfs_share=$(get_yaml_value "system.nfs-config.share")
    local mount_point=$(get_yaml_value "system.nfs-config.mount_point")

    log "NFS Server: $nfs_server"
    log "NFS Share: $nfs_share"
    log "Mount Point: $mount_point"

    if [ -z "$nfs_server" ] || [ -z "$nfs_share" ] || [ -z "$mount_point" ]; then
        log "NFS configuration is incomplete in YAML file"
        lcd_write "ACQUIRE NFS-MODE\nCONFIG ERROR"
        return 1
    fi

    # Always attempt to create the mount point
    log "Attempting to create mount point directory: $mount_point"
    mkdir_output=$(sudo mkdir -p "$mount_point" 2>&1)
    mkdir_status=$?
    log "mkdir command output: $mkdir_output"
    log "mkdir command exit status: $mkdir_status"

    if [ $mkdir_status -ne 0 ]; then
        log "Failed to create mount point directory"
        lcd_write "ACQUIRE NFS-MODE\nMNT DIR FAILED"
        return 1
    fi
    log "Mount point directory created or already exists"

    # Check if already mounted
    if mountpoint -q "$mount_point"; then
        log "NFS share already mounted at $mount_point"
        return 0
    fi

    log "Mounting NFS share $nfs_server:$nfs_share to $mount_point"
    lcd_write "ACQUIRE NFS-MODE\nMOUNTING..."
    
    mount_output=$(sudo mount -t nfs "$nfs_server:$nfs_share" "$mount_point" 2>&1)
    mount_status=$?
    
    log "Mount command output: $mount_output"
    log "Mount command exit status: $mount_status"

    if [ $mount_status -ne 0 ]; then
        log "Failed to mount NFS share"
        lcd_write "ACQUIRE NFS-MODE\nMOUNT FAILED"
        return 1
    else
        log "Successfully mounted NFS share"
    fi

    return 0
}

acquire_image() {
    # Initialize hash storage
    CAPTURED_MD5_FILE="/tmp/captured_md5_$$.txt"
    CAPTURED_SHA1_FILE="/tmp/captured_sha1_$$.txt"
    CAPTURED_SHA256_FILE="/tmp/captured_sha256_$$.txt"
    > "$CAPTURED_MD5_FILE"
    > "$CAPTURED_SHA1_FILE"
    > "$CAPTURED_SHA256_FILE"

    ewfacquire -C "$CASE_NUMBER" -E "$EVIDENCE_NUMBER" -D "$DESCRIPTION" \
               -e "$EXAMINER_NAME" -d sha1 -d sha256 -u -t "$NFS_IMAGE_PATH" -S "$SEGMENT_SIZE" "$DEVICE" 2>&1 | \
    while IFS= read -r line
    do
        echo "$line" | sudo tee -a "$LOGFILE"

        # Capture MD5 hash from ewfacquire output
        if [[ $line =~ MD5\ hash\ calculated\ over\ data:[[:space:]]*([a-f0-9]+) ]]; then
            echo "${BASH_REMATCH[1]}" > "$CAPTURED_MD5_FILE"
            log "Captured MD5 hash: ${BASH_REMATCH[1]}"
        fi

        # Capture SHA1 hash from ewfacquire output
        if [[ $line =~ SHA1\ hash\ calculated\ over\ data:[[:space:]]*([a-f0-9]+) ]]; then
            echo "${BASH_REMATCH[1]}" > "$CAPTURED_SHA1_FILE"
            log "Captured SHA1 hash: ${BASH_REMATCH[1]}"
        fi

        # Capture SHA256 hash from ewfacquire output
        if [[ $line =~ SHA256\ hash\ calculated\ over\ data:[[:space:]]*([a-f0-9]+) ]]; then
            echo "${BASH_REMATCH[1]}" > "$CAPTURED_SHA256_FILE"
            log "Captured SHA256 hash: ${BASH_REMATCH[1]}"
        fi

        if [[ $line =~ Status:\ at\ ([0-9]+)% ]]; then
            acquired_gb=$(echo "$line" | grep -oP 'acquired \K[0-9.]+ GiB')
            total_gb=$(echo "$line" | grep -oP 'of total \K[0-9.]+ GiB')
            speed=$(echo "$line" | grep -oP '[0-9.]+ MiB/s')
            update_lcd "$acquired_gb" "$total_gb" "$speed"
        fi
    done
}

# Main execution
main() {
    RUN_ID=$(date '+%Y%m%d%H%M%S')
    YAML_FILE="/mnt/usb/Imager_config.yaml"
    log "Script started"

    # gpio disabled
    # gpio disabled
    # gpio disabled

    # Detect source device: prioritize SATA HAT port 1, fallback to NVMe HAT, then USB
    SOURCE_DEVICE=$(get_block_device_path "$SATA_PORT1_PATH_TAG" "$NVME_PATH_TAG" "$USBPORT1_PATH_TAG_USB2" "$USBPORT1_PATH_TAG_USB3")
    log "Source device found: $SOURCE_DEVICE"

    if [ -z "$SOURCE_DEVICE" ]; then
        log "No source device found. Aborting."
        lcd_write "NO SOURCE\nDEVICE FOUND"
        exit 1
    fi

    DEVICE="$SOURCE_DEVICE"

    if [ -z "$YAML_FILE" ]; then
        log "No USB drive with YAML file found. Aborting."
        lcd_write "NO CONFIG\nFILE FOUND"
        exit 1
    fi

    UPLOAD_METHOD=$(get_yaml_value "upload_method")
    IMAGE_NAME=$(get_yaml_value "imager-config.image_name")
    NFS_MOUNT_POINT=$(get_yaml_value "system.nfs-config.mount_point")
    NFS_IMAGE_PATH="${NFS_MOUNT_POINT}/${IMAGE_NAME}"
    CASE_NUMBER=$(get_yaml_value "imager-config.case_number")
    EVIDENCE_NUMBER=$(get_yaml_value "imager-config.evidence_number")
    EXAMINER_NAME=$(get_yaml_value "imager-config.examiner_name")
    DESCRIPTION=$(get_yaml_value "imager-config.description")
    log "Upload method: $UPLOAD_METHOD"
    log "Image name: $IMAGE_NAME"
    log "NFS mount point: $NFS_MOUNT_POINT"
    log "NFS image path: $NFS_IMAGE_PATH"

    if mount_nfs; then
        lcd_write "ACQUIRE NFS-MODE\nINITIALIZING..."
        blink_led 0.1 &
        BLINK_LED_PID=$!

        if acquire_image; then
            lcd_write "ACQUIRE NFS-MODE\nSUCCESSFUL"
            log "Successfully acquired image for $DEVICE directly to NFS mount $NFS_MOUNT_POINT"
        else
            log "Failed to acquire image for $DEVICE to NFS mount"
            kill "$BLINK_LED_PID"
            # gpio disabled
            lcd_write "ACQUIRE NFS-MODE\nFAILED"
            exit 1
        fi

        kill "$BLINK_LED_PID"
        # gpio disabled
# Insert this after line 239 (after "Successfully acquired image...")

        # Write completion data for agent to consume
        log "Writing completion data for agent..."
        COMPLETION_FILE="/tmp/imaging_completion.json"
        
        # Find all E01 segments for this image
        IMAGE_FILES=$(find "$NFS_MOUNT_POINT" -name "${IMAGE_NAME}*.E01" -o -name "${IMAGE_NAME}*.e01" 2>/dev/null)
        
        if [ -n "$IMAGE_FILES" ]; then
            # Get total size of all segments
            TOTAL_SIZE=0
            FIRST_FILE=""
            for file in $IMAGE_FILES; do
                if [ -z "$FIRST_FILE" ]; then
                    FIRST_FILE="$file"
                fi
                FILE_SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                TOTAL_SIZE=$((TOTAL_SIZE + FILE_SIZE))
            done
            
            # Read captured hashes from temp files
            CAPTURED_MD5=""
            CAPTURED_SHA1=""
            CAPTURED_SHA256=""
            if [ -f "/tmp/captured_md5_$$.txt" ]; then
                CAPTURED_MD5=$(cat "/tmp/captured_md5_$$.txt")
                rm -f "/tmp/captured_md5_$$.txt"
                log "Using captured MD5: $CAPTURED_MD5"
            fi
            if [ -f "/tmp/captured_sha1_$$.txt" ]; then
                CAPTURED_SHA1=$(cat "/tmp/captured_sha1_$$.txt")
                rm -f "/tmp/captured_sha1_$$.txt"
                log "Using captured SHA1: $CAPTURED_SHA1"
            fi
            if [ -f "/tmp/captured_sha256_$$.txt" ]; then
                CAPTURED_SHA256=$(cat "/tmp/captured_sha256_$$.txt")
                rm -f "/tmp/captured_sha256_$$.txt"
                log "Using captured SHA256: $CAPTURED_SHA256"
            fi
            
            # Collect SMART data from source device
            log "Collecting SMART data from source device: $DEVICE"
            SMART_DATA_FILE="/tmp/smart_data_$$.json"
            if command -v smartctl &> /dev/null; then
                sudo smartctl -a --json "$DEVICE" > "$SMART_DATA_FILE" 2>/dev/null || true
            fi
            
            # Build JSON completion data
            cat > "$COMPLETION_FILE" << JSONEOF
{
    "output_path": "$FIRST_FILE",
    "image_size": $TOTAL_SIZE,
    "nfs_mode": true,
    "mount_point": "$NFS_MOUNT_POINT"
JSONEOF

            # Add hashes if captured
            if [ -n "$CAPTURED_MD5" ]; then
                cat >> "$COMPLETION_FILE" << JSONEOF
,
    "source_md5": "$CAPTURED_MD5",
    "image_md5": "$CAPTURED_MD5"
JSONEOF
            fi
            if [ -n "$CAPTURED_SHA1" ]; then
                cat >> "$COMPLETION_FILE" << JSONEOF
,
    "source_sha1": "$CAPTURED_SHA1",
    "image_sha1": "$CAPTURED_SHA1"
JSONEOF
            fi
            if [ -n "$CAPTURED_SHA256" ]; then
                cat >> "$COMPLETION_FILE" << JSONEOF
,
    "source_sha256": "$CAPTURED_SHA256",
    "image_sha256": "$CAPTURED_SHA256"
JSONEOF
            fi
            
            # Add SMART data if available
            if [ -f "$SMART_DATA_FILE" ]; then
                cat >> "$COMPLETION_FILE" << JSONEOF
,
    "smart_data": $(cat "$SMART_DATA_FILE")
JSONEOF
                rm -f "$SMART_DATA_FILE"
            fi
            
            # Close JSON
            echo "}" >> "$COMPLETION_FILE"
            
            log "Completion data written to $COMPLETION_FILE"
            log "Output path: $FIRST_FILE, Total size: $TOTAL_SIZE bytes, MD5: $CAPTURED_MD5, SHA1: $CAPTURED_SHA1, SHA256: $CAPTURED_SHA256"
        else
            log "Warning: Could not find E01 files in $NFS_MOUNT_POINT"
        fi

        static_led_ok
        echo "DONE"
    else
        log "Failed to mount NFS share. Aborting."
        exit 1
    fi

    # Cleanup
    umount $NFS_MOUNT_POINT
    rm -rf $NFS_MOUNT_POINT
}

# Run the main function
main
