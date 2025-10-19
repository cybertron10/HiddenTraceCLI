#!/bin/bash

# Batch XSS Scanner Script
# Processes domains in batches of 100 from domains.txt

# Configuration
BATCH_SIZE=100
BATCH_COUNTER=1

# Check if input file is provided as argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domains_file>"
    echo "Example: $0 domains.txt"
    exit 1
fi

INPUT_FILE="$1"
WORKING_FILE="domains_working.txt"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found!"
    exit 1
fi

# Copy input file to current directory for processing
echo "Copying $INPUT_FILE to current directory as $WORKING_FILE..."
cp "$INPUT_FILE" "$WORKING_FILE"

# Get total number of domains
TOTAL_DOMAINS=$(wc -l < "$WORKING_FILE")
echo "Total domains to process: $TOTAL_DOMAINS"
echo "Processing in batches of $BATCH_SIZE"
echo "----------------------------------------"

# Process domains in batches
while [ -s "$WORKING_FILE" ]; do
    echo "Processing batch $BATCH_COUNTER..."
    
    # Create temporary file with first 10 domains
    head -n "$BATCH_SIZE" "$WORKING_FILE" > "batch_$BATCH_COUNTER.txt"
    
    # Count domains in this batch
    BATCH_DOMAINS=$(wc -l < "batch_$BATCH_COUNTER.txt")
    echo "  Batch $BATCH_COUNTER: $BATCH_DOMAINS domains"
    
    # Clean up scan directory before running axiom-scan
    echo "  Cleaning up scan directory..."
    /bin/rm -rf /home/op/scan/*
    
    # Run axiom-scan on this batch with unique output name
    echo "  Running axiom-scan on batch $BATCH_COUNTER..."
    axiom-scan "batch_$BATCH_COUNTER.txt" -m xss-scan -o "xss_batch_$BATCH_COUNTER.txt"
    
    # Check if axiom-scan was successful
    if [ $? -eq 0 ]; then
        echo "  ✓ Batch $BATCH_COUNTER completed successfully"
        
        # Check if result file is empty and remove it if so
        if [ -f "xss_batch_$BATCH_COUNTER.txt" ]; then
            if [ ! -s "xss_batch_$BATCH_COUNTER.txt" ]; then
                echo "  No XSS results found, removing empty file..."
                rm -f "xss_batch_$BATCH_COUNTER.txt"
            else
                echo "  XSS results found and saved to xss_batch_$BATCH_COUNTER.txt"
            fi
        fi
    else
        echo "  ✗ Batch $BATCH_COUNTER failed"
        # Remove empty result file if scan failed
        rm -f "xss_batch_$BATCH_COUNTER.txt"
    fi
    
    # Remove processed domains from the working file
    tail -n +$((BATCH_SIZE + 1)) "$WORKING_FILE" > "temp_domains.txt"
    mv "temp_domains.txt" "$WORKING_FILE"
    
    # Clean up temporary batch file (keep the result file)
    rm -f "batch_$BATCH_COUNTER.txt"
    
    # Increment counter
    BATCH_COUNTER=$((BATCH_COUNTER + 1))
    
    # Show remaining domains
    REMAINING=$(wc -l < "$WORKING_FILE" 2>/dev/null || echo "0")
    echo "  Remaining domains: $REMAINING"
    echo "----------------------------------------"
    
    # Optional: Add a small delay between batches
    sleep 2
done

echo "All batches completed!"
echo "Result files created:"
ls -la xss_batch_*.txt 2>/dev/null | wc -l | xargs echo "Total result files:"
echo "Files:"
ls -la xss_batch_*.txt 2>/dev/null

# Clean up working file
echo "Cleaning up working file..."
rm -f "$WORKING_FILE"
echo "Original file $INPUT_FILE remains unchanged."
