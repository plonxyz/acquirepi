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
LOGFILE="/var/log/acquire.log"
USB_MOUNT_PATH="/mnt/usb"
YAML_FILE="$USB_MOUNT_PATH/Imager_config.yaml"
LED_PATH="/sys/class/leds/ACT/brightness"
GPIO_PIN_LED=5
GPIO_PIN_OK=6
SEGMENT_SIZE="2199023255552"
LCD_WRITE_SCRIPT="/usr/local/bin/lcd-write.sh"

# Functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $RUN_ID - $1" >> $LOGFILE 2>&1
}

led_control() {
    # Pi 5 ACT LED is active-low: 1=OFF, 0=ON
    # Disable trigger first to prevent it from overriding brightness
    echo "none" | sudo tee /sys/class/leds/ACT/trigger > /dev/null 2>&1
    echo "$1" | sudo tee $LED_PATH > /dev/null
}

blink_led() {
    local interval=$1
    while true; do
        led_control 0  # ON (active-low)
        sleep $interval
        led_control 1  # OFF (active-low)
        sleep $interval
    done
}

static_led_ok() {
    # Solid ON for 5 seconds then OFF
    led_control 0  # ON (active-low)
    sleep 5
    led_control 1  # OFF (active-low)
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
               -e "$EXAMINER_NAME" -d sha1 -d sha256 -u -t "$1" -S "$SEGMENT_SIZE" "$DEVICE" 2>&1 | \
    while IFS= read -r line
    do
        echo "$line"    
        echo "$line" >> "$LOGFILE"

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

        # Update LCD with progress if available
        if [[ $line =~ Status:\ at\ ([0-9]+)% ]]; then
            acquired_gb=$(echo "$line" | grep -oP 'acquired \K[0-9.]+ GiB' || true)
            total_gb=$(echo "$line" | grep -oP 'of total \K[0-9.]+ GiB' || true)
            if [ -n "$acquired_gb" ] && [ -n "$total_gb" ]; then
                lcd_write "ACQUIRE DISKMODE\n${acquired_gb}/${total_gb}" true
            fi
        fi
    done
}

lcd_write() {
    if [ -x "$LCD_WRITE_SCRIPT" ]; then
        $LCD_WRITE_SCRIPT "$1" "$2" > /dev/null 2>&1
    else
        echo "LCD message (not displayed): $1"
    fi
}

process_disk_mode() {
    lcd_write "ACQUIRE DISKMODE \n  IN PROGRESS  " true
    if acquire_image "$DESTINATION"; then
        log "Successfully acquired image for $DEVICE"
        lcd_write "ACQUIRE DISKMODE \n   SUCCESSFUL  " true
        log "Successfully saved image to $DESTINATION.E01 using copy-to-disk"
        return 0
    else
        lcd_write "ACQUIRE DISKMODE \n     ERROR     " true
        log "Failed to acquire image for $DEVICE"
        return 1
    fi
}

# Main execution
main() {
    RUN_ID=$(date '+%Y%m%d%H%M%S')

    # Read configuration from YAML
    DEVICE="/dev/source_disk"
    DEVICE2="/mnt/destination"
    IMAGE_NAME=$(yq e '.imager-config.image_name' $YAML_FILE)
    MOUNT_POINT="${DEVICE2}"
    DESTINATION="${MOUNT_POINT}/${IMAGE_NAME}"
    CASE_NUMBER=$(yq e '.imager-config.case_number' $YAML_FILE)
    EVIDENCE_NUMBER=$(yq e '.imager-config.evidence_number' $YAML_FILE)
    EXAMINER_NAME=$(yq e '.imager-config.examiner_name' $YAML_FILE)
    DESCRIPTION=$(yq e '.imager-config.description' $YAML_FILE)

    log "Script started for device: $DEVICE"
    log "Starting acquisition for device: $DEVICE"

    blink_led 0.1 &
    BLINK_LED_PID=$!

    process_disk_mode
    result=$?

    kill $BLINK_LED_PID

    if [ $result -eq 0 ]; then
        static_led_ok
        
        # Create completion file for post-acquisition verification
        COMPLETION_FILE="/tmp/imaging_completion.json"
        OUTPUT_PATH="${DESTINATION}.E01"

        # Get image size if file exists
        IMAGE_SIZE=0
        if [ -f "$OUTPUT_PATH" ]; then
            IMAGE_SIZE=$(stat -c %s "$OUTPUT_PATH" 2>/dev/null || echo 0)
        fi

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

        # Build JSON completion data
        cat > "$COMPLETION_FILE" <<JSON_EOF
{
    "output_path": "${OUTPUT_PATH}",
    "image_size": ${IMAGE_SIZE},
    "upload_method": "disk"
JSON_EOF

        # Add hashes if captured
        if [ -n "$CAPTURED_MD5" ]; then
            cat >> "$COMPLETION_FILE" <<JSON_EOF
,
    "source_md5": "$CAPTURED_MD5",
    "image_md5": "$CAPTURED_MD5"
JSON_EOF
        fi
        if [ -n "$CAPTURED_SHA1" ]; then
            cat >> "$COMPLETION_FILE" <<JSON_EOF
,
    "source_sha1": "$CAPTURED_SHA1",
    "image_sha1": "$CAPTURED_SHA1"
JSON_EOF
        fi
        if [ -n "$CAPTURED_SHA256" ]; then
            cat >> "$COMPLETION_FILE" <<JSON_EOF
,
    "source_sha256": "$CAPTURED_SHA256",
    "image_sha256": "$CAPTURED_SHA256"
JSON_EOF
        fi

        # Close JSON
        echo "}" >> "$COMPLETION_FILE"

        log "Created completion file: $COMPLETION_FILE"
        log "Hashes - MD5: $CAPTURED_MD5, SHA1: $CAPTURED_SHA1, SHA256: $CAPTURED_SHA256"
        
        echo "DONE"
    else
        exit 1
    fi

    log "Imaged $DEVICE and saved to $DESTINATION.E01"
}

# Run the main function
main
