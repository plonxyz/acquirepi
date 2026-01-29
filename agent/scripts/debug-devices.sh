#!/bin/bash
# Diagnostic script to show all block devices and their udev path tags

echo "=== All Block Devices ==="
lsblk -lno NAME,TYPE,SIZE

echo ""
echo "=== Device Path Tags ==="
for device in $(lsblk -lno NAME,TYPE | grep -E "\<disk\>" | awk '{print $1}'); do
    if [[ "$device" == "mmcblk0" ]]; then
        continue
    fi

    echo ""
    echo "Device: /dev/$device"
    udevadm info --query=all --name="/dev/$device" | grep -E "(ID_PATH=|ID_PATH_TAG=|ID_BUS=|DEVTYPE=)"
done

echo ""
echo "=== Expected Path Tags ==="
echo "SATA Port 1: platform-1000110000_pcie-pci-0000_03_00_0-ata-1_0"
echo "SATA Port 2: platform-1000110000_pcie-pci-0000_03_00_0-ata-2_0"
echo "NVMe (current): platform-1000110000_pcie-pci-0000_04_00_0-nvme-1"
echo ""
echo "=== Testing device detection ==="
source /usr/local/bin/usb-handler.sh
echo "Source device: $(get_block_device_path "$SATA_PORT1_PATH_TAG" "$NVME_PATH_TAG" "$USBPORT1_PATH_TAG_USB2" "$USBPORT1_PATH_TAG_USB3")"
echo "Destination device: $(get_block_device_path "$SATA_PORT2_PATH_TAG" "$USBPORT2_PATH_TAG_USB2" "$USBPORT2_PATH_TAG_USB3")"
