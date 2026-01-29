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
MOUNT_POINT="/mnt/destination"
LOGFILE="/var/log/copy_usb.log"

# Functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

cleanup() {
    log "Starting cleanup..."
    if mountpoint -q "$MOUNT_POINT"; then
        umount "$MOUNT_POINT"
        log "Unmounted $MOUNT_POINT"
    fi
    rm -f /dev/source_disk /dev/destination_disk /dev/destination_disk1
    log "Removed symlinks"
    log "Cleanup completed"
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

get_available_devices() {
    # Returns all available disks excluding boot device, zram, config stick, and mounted devices
    # Sorted by size (smallest first)
    local devices=()
    local config_device=""

    # Find config stick device by UUID
    if [ -n "$CONFIG_STICK_UUID" ]; then
        config_device=$(blkid -U "$CONFIG_STICK_UUID" 2>/dev/null | sed 's/[0-9]*$//')
    fi

    # Get disk devices (not partitions) sorted by size
    while IFS= read -r line; do
        local device=$(echo "$line" | awk '{print $1}')

        # Skip the boot device (mmcblk*)
        [[ "$device" == mmcblk* ]] && continue
        # Skip zram devices
        [[ "$device" == zram* ]] && continue
        # Skip loop devices
        [[ "$device" == loop* ]] && continue
        # Skip config stick
        [[ "/dev/$device" == "$config_device" ]] && continue

        # Check if device or any of its partitions are mounted
        local is_mounted=0
        while IFS= read -r mnt_line; do
            if [[ -n "$mnt_line" ]]; then
                is_mounted=1
                break
            fi
        done < <(lsblk -lno MOUNTPOINT "/dev/$device" 2>/dev/null | grep -v "^$")

        if [ $is_mounted -eq 0 ]; then
            devices+=("/dev/$device")
        fi
    done < <(lsblk -lnbo NAME,SIZE,TYPE | awk '$3=="disk" {print $1, $2}' | sort -k2 -n)

    echo "${devices[@]}"
}

flexible_device_detection() {
    # Flexible device detection - assigns available devices as source and destination
    # Uses size-based logic: smaller disk = source, larger disk = destination
    log "Using flexible device detection method (size-based: smaller=source, larger=destination)"

    local available_devices=($(get_available_devices))
    local num_devices=${#available_devices[@]}

    log "Found $num_devices available device(s): ${available_devices[*]}"

    if [ $num_devices -lt 2 ]; then
        log "Error: Need at least 2 devices for disk-to-disk imaging, found only $num_devices"
        return 1
    fi

    # If source was already found, find the largest device that's not the source for destination
    if [ -n "$SOURCE_DEVICE" ]; then
        for ((i=${#available_devices[@]}-1; i>=0; i--)); do
            if [ "${available_devices[i]}" != "$SOURCE_DEVICE" ]; then
                DESTINATION_DEVICE="${available_devices[i]}"
                log "Flexible detection: Destination device (largest available): $DESTINATION_DEVICE"
                break
            fi
        done
    # If destination was already found, find the smallest device that's not the destination for source
    elif [ -n "$DESTINATION_DEVICE" ]; then
        for device in "${available_devices[@]}"; do
            if [ "$device" != "$DESTINATION_DEVICE" ]; then
                SOURCE_DEVICE="$device"
                log "Flexible detection: Source device (smallest available): $SOURCE_DEVICE"
                break
            fi
        done
    # Neither found - smallest = source, largest = destination
    else
        SOURCE_DEVICE="${available_devices[0]}"
        DESTINATION_DEVICE="${available_devices[-1]}"

        # Get sizes for logging
        local src_size=$(lsblk -lnbo SIZE "$SOURCE_DEVICE" 2>/dev/null | head -1)
        local dst_size=$(lsblk -lnbo SIZE "$DESTINATION_DEVICE" 2>/dev/null | head -1)
        log "Size-based detection: Source=$SOURCE_DEVICE ($(numfmt --to=iec $src_size 2>/dev/null || echo $src_size)), Destination=$DESTINATION_DEVICE ($(numfmt --to=iec $dst_size 2>/dev/null || echo $dst_size))"
    fi

    if [ -z "$SOURCE_DEVICE" ] || [ -z "$DESTINATION_DEVICE" ]; then
        log "Error: Failed to assign source and destination devices"
        return 1
    fi

    return 0
}

create_symlink() {
    local device=$1
    local link_name=$2
    ln -sf "$device" "$link_name"
    log "Created symbolic link: $link_name -> $device"
}

mount_destination() {
    if [ ! -d "$MOUNT_POINT" ]; then
        mkdir -p "$MOUNT_POINT"
        log "Created mount point: $MOUNT_POINT"
    fi
    if ! mountpoint -q "$MOUNT_POINT"; then
        mount -t exfat /dev/destination_disk1 "$MOUNT_POINT"
        log "Mounted /dev/destination_disk1 to $MOUNT_POINT"
    else
        log "$MOUNT_POINT is already mounted."
    fi
}

# Main script execution
main() {
    log "Script started"

    # Run cleanup before starting
    cleanup

    log "Finding source device..."
    # Detect source device: prioritize SATA HAT port 1, fallback to NVMe HAT, then USB
    SOURCE_DEVICE=$(get_block_device_path "$SATA_PORT1_PATH_TAG" "$NVME_PATH_TAG" "$USBPORT1_PATH_TAG_USB2" "$USBPORT1_PATH_TAG_USB3")
    if [ -n "$SOURCE_DEVICE" ]; then
        log "Source device found via hardware path: $SOURCE_DEVICE"
    else
        log "Source device not found via hardware path, will use flexible detection"
    fi

    log "Finding destination device..."
    # Detect destination device: prioritize SATA HAT port 2, fallback to USB
    DESTINATION_DEVICE=$(get_block_device_path "$SATA_PORT2_PATH_TAG" "$USBPORT2_PATH_TAG_USB2" "$USBPORT2_PATH_TAG_USB3")
    if [ -n "$DESTINATION_DEVICE" ]; then
        log "Destination device found via hardware path: $DESTINATION_DEVICE"
    else
        log "Destination device not found via hardware path, will use flexible detection"
    fi

    # If either device not found, use flexible detection
    if [ -z "$SOURCE_DEVICE" ] || [ -z "$DESTINATION_DEVICE" ]; then
        log "Attempting flexible device detection..."
        if ! flexible_device_detection; then
            log "Error: Flexible device detection failed"
            exit 1
        fi
    fi

    # Verify we have both devices
    if [ -z "$SOURCE_DEVICE" ] || [ -z "$DESTINATION_DEVICE" ]; then
        log "Error: One or both devices not found."
        exit 1
    fi

    # Log final device assignment
    log "Final device assignment - Source: $SOURCE_DEVICE, Destination: $DESTINATION_DEVICE"

    create_symlink "$SOURCE_DEVICE" "/dev/source_disk"
    create_symlink "$DESTINATION_DEVICE" "/dev/destination_disk"

    DESTINATION_PARTITION=$(lsblk -lno NAME,TYPE | grep -E "^${DESTINATION_DEVICE##*/}[0-9]" | awk '{print $1}' | tail -n 1)
    if [ -z "$DESTINATION_PARTITION" ]; then
        log "Error: Destination partition not found."
        exit 1
    fi

    create_symlink "/dev/$DESTINATION_PARTITION" "/dev/destination_disk1"

    if [ -L /dev/source_disk ] && [ -L /dev/destination_disk ] && [ -L /dev/destination_disk1 ]; then
        log "All symbolic links created successfully. Running imager script..."
        mount_destination
        if mountpoint -q "$MOUNT_POINT"; then
            log "Starting imager.sh"
            /usr/local/bin/imager.sh
            IMAGER_EXIT_CODE=$?
            log "imager.sh completed with exit code $IMAGER_EXIT_CODE"

            if [ $IMAGER_EXIT_CODE -eq 0 ]; then
                log "Imaging completed successfully. Unmounting..."
                cleanup
            else
                log "Error: imager.sh failed with exit code $IMAGER_EXIT_CODE"
                cleanup
                exit 1
            fi
        else
            log "Error: Failed to mount the destination partition."
            cleanup
            exit 1
        fi
    else
        log "Error: One or both USB sticks are missing or not recognized."
        cleanup
        exit 1
    fi
    # Mount point cleaned up in cleanup function
}

# Run the main function
main
