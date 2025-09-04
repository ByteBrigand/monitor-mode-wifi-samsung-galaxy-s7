#!/system/bin/sh

# Set LD_PRELOAD for all commands
export LD_PRELOAD=/system/lib64/libnexmonitor.so

# Function to cleanup on exit
cleanup() {
    echo -e "\nStopping capture..."
    if [ -n "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null
    fi
    echo "Restoring monitor mode..."
    nexutil --monitor=0
    exit 0
}

# Function to show spinning cursor and packet count
show_status() {
    SPIN='-\|/'
    i=0
    while true; do
        i=$(( (i+1) %4 ))
        if [ -f "$OUTPUT_FILE" ]; then
            COUNT=$(tcpdump -r "$OUTPUT_FILE" 2>/dev/null | wc -l)
            echo -ne "\rCapturing ${SPIN:$i:1} EAPOL packets captured: $COUNT"
        else
            echo -ne "\rCapturing ${SPIN:$i:1}"
        fi
        sleep 0.5
    done
}

# Handle Ctrl+C
trap cleanup INT TERM

# Parse arguments
INTERFACE="wlan0"
CHANNEL=""
OUTPUT=""
BSSID=""
HOP=0

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -c|--channel)
            CHANNEL="$2"
            shift 2
            ;;
        -w|--write)
            OUTPUT="$2"
            shift 2
            ;;
        -b|--bssid)
            BSSID="$2"
            shift 2
            ;;
        --hop)
            HOP=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set monitor mode and verify
echo "Setting monitor mode..."
nexutil --monitor=1
sleep 1  # Brief delay after setting monitor mode

MONITOR_MODE=$(nexutil --monitor | cut -d' ' -f2)
if [ "$MONITOR_MODE" != "1" ]; then
    echo "Failed to set monitor mode!"
    exit 1
fi
echo "Monitor mode set successfully"

# Set channel if specified and verify
if [ -n "$CHANNEL" ]; then
    echo "Setting channel to $CHANNEL..."
    nexutil --chanspec=$CHANNEL
    sleep 1  # Brief delay after setting channel
elif [ "$HOP" -eq 1 ]; then
    echo "Channel hopping enabled..."
    # Start channel hopping in background
    (while true; do
        for ch in 1 6 11 36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165; do
            nexutil --chanspec=$ch
            sleep 2
        done
    done) &
    HOPPING_PID=$!
fi

# Build tcpdump filter
FILTER="ether proto 0x888e"
if [ -n "$BSSID" ]; then
    FILTER="$FILTER and (wlan addr1 $BSSID or wlan addr2 $BSSID)"
fi

# Build output filename if specified
if [ -n "$OUTPUT" ]; then
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    OUTPUT_FILE="${OUTPUT}-${TIMESTAMP}.pcap"
    echo "Saving capture to: $OUTPUT_FILE"
    tcpdump -i "$INTERFACE" -s 0 -w "$OUTPUT_FILE" -v "$FILTER" &
else
    # Just display packets if no output file specified
    tcpdump -i "$INTERFACE" -s 0 -v "$FILTER" &
fi

TCPDUMP_PID=$!

echo "Starting capture on $INTERFACE"
echo "Filter: $FILTER"
echo "Debug Info:"
echo "Current monitor mode: $(nexutil --monitor)"

# Start status display in background
show_status &
STATUS_PID=$!

# Wait for tcpdump to finish or user interrupt
wait $TCPDUMP_PID

# Cleanup
if [ -n "$STATUS_PID" ]; then
    kill $STATUS_PID 2>/dev/null
fi
if [ -n "$HOPPING_PID" ]; then
    kill $HOPPING_PID 2>/dev/null
fi
cleanup
