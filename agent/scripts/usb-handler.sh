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
# SATA HAT paths (supports 2 SATA devices via PCIe SATA controller)
SATA_PORT1_PATH_TAG="platform-1000110000_pcie-pci-0000_03_00_0-ata-1_0"
SATA_PORT2_PATH_TAG="platform-1000110000_pcie-pci-0000_03_00_0-ata-2_0"
# NVMe HAT path (single NVMe device via PCIe)
NVME_PATH_TAG="platform-1000110000_pcie-pci-0000_04_00_0-nvme-1"
# Legacy USB paths (kept for backwards compatibility)
USBPORT1_PATH_TAG_USB2="platform-xhci-hcd_1-usb-0_1_3_1_0-scsi-0_0_0_0"
USBPORT1_PATH_TAG_USB3="platform-xhci-hcd_1-usb-0_1_1_0-scsi-0_0_0_0"
USBPORT2_PATH_TAG_USB2="platform-xhci-hcd_1-usb-0_1_2_1_0-scsi-0_0_0_0"
USBPORT2_PATH_TAG_USB3="platform-xhci-hcd_0-usb-0_1_1_0-scsi-0_0_0_0"
# Config stick UUID (to exclude from source/destination detection)
CONFIG_STICK_UUID="937C-8BC2"
LOG_FILE="/var/log/handler.log"
CONFIG_FILE="/mnt/usb/Imager_config.yaml"
LCD_WRITE_SCRIPT="/usr/local/bin/lcd-write.sh"
CONFIG_CLIENT_SCRIPT="/usr/local/bin/acquirepi-config-client.sh"

# Functions
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

get_upload_method() {
    if [ -f "$CONFIG_FILE" ] && command -v yq &> /dev/null; then
        yq eval '.system.upload_method' "$CONFIG_FILE"
    else
        echo ""
    fi
}

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

lcd_write() {
    if [ -x "$LCD_WRITE_SCRIPT" ]; then
        $LCD_WRITE_SCRIPT "$1" > /dev/null 2>&1
    else
        echo "LCD message (not displayed): $1"
    fi
}

run_imager_script() {
    if [ -x "$1" ]; then
        "$1"
        return $?
    else
        log_message "Error: Script $1 not found or not executable"
        return 1
    fi
}

mount_nfs_share() {
    local nfs_server=$(yq eval '.system.nfs-config.server' "$CONFIG_FILE")
    local nfs_share=$(yq eval '.system.nfs-config.share' "$CONFIG_FILE")
    local mount_point=$(yq eval '.system.nfs-config.mount_point' "$CONFIG_FILE")

    if [ ! -d "$mount_point" ]; then
        sudo mkdir -p "$mount_point"
    fi

    if ! mountpoint -q "$mount_point"; then
        sudo mount -t nfs "$nfs_server:$nfs_share" "$mount_point"
        if [ $? -eq 0 ]; then
            log_message "Mounted NFS share $nfs_server:$nfs_share to $mount_point"
        else
            log_message "Failed to mount NFS share $nfs_server:$nfs_share"
            return 1
        fi
    fi
}

detect_devices_by_size() {
    # Fallback detection: find source and destination by size
    # Excludes: boot device (mmcblk*), loop devices, config stick (by UUID)
    # Returns: smaller disk = source, larger disk = destination
    local config_device=""
    local available_devices=()

    # Find config stick device by UUID
    if [ -n "$CONFIG_STICK_UUID" ]; then
        config_device=$(blkid -U "$CONFIG_STICK_UUID" 2>/dev/null | sed 's/[0-9]*$//')
    fi

    # Get all disk devices (not partitions) with their sizes, sorted by size
    while IFS= read -r line; do
        local dev=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')

        # Skip boot device (mmcblk*)
        [[ "$dev" == mmcblk* ]] && continue
        # Skip loop devices
        [[ "$dev" == loop* ]] && continue
        # Skip zram devices
        [[ "$dev" == zram* ]] && continue
        # Skip config stick
        [[ "/dev/$dev" == "$config_device" ]] && continue

        available_devices+=("/dev/$dev:$size")
    done < <(lsblk -lnbo NAME,SIZE,TYPE | awk '$3=="disk" {print $1, $2}' | sort -k2 -n)

    # Need at least 2 devices for source and destination
    if [ ${#available_devices[@]} -lt 2 ]; then
        log_message "Size-based detection: Not enough devices found (need 2, found ${#available_devices[@]})"
        return 1
    fi

    # Smallest = source, largest = destination
    SOURCE_DEVICE=$(echo "${available_devices[0]}" | cut -d: -f1)
    DESTINATION_DEVICE=$(echo "${available_devices[-1]}" | cut -d: -f1)

    local src_size=$(echo "${available_devices[0]}" | cut -d: -f2)
    local dst_size=$(echo "${available_devices[-1]}" | cut -d: -f2)

    log_message "Size-based detection: Source=$SOURCE_DEVICE ($(numfmt --to=iec $src_size)), Destination=$DESTINATION_DEVICE ($(numfmt --to=iec $dst_size))"
    return 0
}

# Main execution
main() {
    log_message "acquirepi USB Handler started"

    # First, try to get configuration from management server
    if [ -x "$CONFIG_CLIENT_SCRIPT" ]; then
        log_message "Running config client to fetch configuration..."
        if "$CONFIG_CLIENT_SCRIPT"; then
            log_message "Configuration obtained successfully"
        else
            log_message "Config client failed, checking for existing config..."
            if [ ! -f "$CONFIG_FILE" ]; then
                log_message "ERROR: No configuration available"
                lcd_write "   NO CONFIG   \n   AVAILABLE   "
                exit 1
            fi
        fi
    else
        log_message "Config client script not found, using existing config if available"
    fi

    UPLOAD_METHOD=$(get_upload_method)
    log_message "Upload method: $UPLOAD_METHOD"

    # Detect source device: prioritize SATA HAT port 1, fallback to NVMe HAT, then USB
    SOURCE_DEVICE=$(get_block_device_path "$SATA_PORT1_PATH_TAG" "$NVME_PATH_TAG" "$USBPORT1_PATH_TAG_USB2" "$USBPORT1_PATH_TAG_USB3")

    # Detect destination device: prioritize SATA HAT port 2, fallback to USB
    DESTINATION_DEVICE=$(get_block_device_path "$SATA_PORT2_PATH_TAG" "$USBPORT2_PATH_TAG_USB2" "$USBPORT2_PATH_TAG_USB3")

    # Fallback to size-based detection if path-based detection failed
    if [ -z "$SOURCE_DEVICE" ] || [ -z "$DESTINATION_DEVICE" ]; then
        log_message "Path-based detection incomplete (Source: $SOURCE_DEVICE, Dest: $DESTINATION_DEVICE), trying size-based fallback..."
        if detect_devices_by_size; then
            log_message "Using size-based detection results"
        else
            log_message "Size-based detection also failed"
        fi
    else
        log_message "Path-based detection: Source=$SOURCE_DEVICE, Destination=$DESTINATION_DEVICE"
    fi

    case "$UPLOAD_METHOD" in
        "s3")
            lcd_write "     acquirepi \n S3-MODE"
            if [ -n "$SOURCE_DEVICE" ]; then
                if run_imager_script "/usr/local/bin/s3-imager.sh"; then
                    log_message "s3-imager.sh completed successfully"
                else
                    log_message "Error: s3-imager.sh failed"
                    lcd_write "     ERROR \n S3 IMAGER FAIL"
                fi
            else
                log_message "Source device not connected for S3 mode"
                lcd_write "     ERROR \n NO SOURCE DISK"
            fi
            ;;
        "disk")
            lcd_write "     acquirepi \n IMAGE TO DISK "
            if [ -n "$SOURCE_DEVICE" ] && [ -n "$DESTINATION_DEVICE" ]; then
                if run_imager_script "/usr/local/bin/disk_mount.sh"; then
                    log_message "copy_usb.sh completed successfully"
                else
                    log_message "Error: copy_usb.sh failed"
                    lcd_write "     ERROR \n COPY FAILED"
                fi
            else
                log_message "Source or destination device not connected. Source: $SOURCE_DEVICE, Destination: $DESTINATION_DEVICE"
                lcd_write "     ERROR \n DISK MISSING"
            fi
            ;;
        "nfs")
            lcd_write "     acquirepi \n NFS-TARGET MODE"
            if [ -n "$SOURCE_DEVICE" ]; then
                if mount_nfs_share; then
                    log_message "Starting nfs-imager.sh, USB port 1 connected and mounted, NFS share mounted"
                    run_imager_script "/usr/local/bin/nfs-imager.sh"
                else
                    log_message "Failed to mount NFS share"
                    lcd_write "  NFS ERROR \n MOUNT FAILED "
                fi
            else
                log_message "Source device not connected for NFS-target mode"
                lcd_write "  DISK ERROR \n NOT CONNECTED"
            fi
            ;;
        *)
            log_message "Unknown upload method or config file not found"
            lcd_write "     ERROR \n UNKNOWN MODE "
            ;;    
    esac
}

# Run the main function
main
