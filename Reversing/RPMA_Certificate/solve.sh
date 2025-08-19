#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

BINARY="./target/release/flag_checker"
FLAG_LENGTH=49
CHARSET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!@#$%^&*()"

found_flag=""
results_file="qemu_results_$(date +%Y%m%d_%H%M%S).log"
temp_log="/tmp/qemu_icount.log"

echo -e "${BLUE}solve_script${NC}"
echo "========================================================"
echo "binary: $BINARY"
echo "flag length: $FLAG_LENGTH"
echo ""

if [ ! -f "$BINARY" ]; then
    echo -e "${RED}ERROR: $BINARY not found${NC}"
    exit 1
fi

echo -e "${YELLOW} please install perf and qemu${NC}"

count_instructions() {
    local input="$1"
    local temp_file=$(mktemp)
    
    timeout 30s perf stat -e instructions -o "$temp_file" "$BINARY" "$input" >/dev/null 2>&1 || true
    local instructions=$(grep "instructions" "$temp_file" 2>/dev/null | awk '{print $1}' | tr -d ',' || echo "0")
    rm -f "$temp_file"
    echo "$instructions"
}

test_character() {
    local position=$1
    local char=$2
    local current_flag="$3"
    
    local test_input="${current_flag}${char}"
    while [ ${#test_input} -lt $FLAG_LENGTH ]; do
        test_input="${test_input}A"
    done
    
    count_instructions "$test_input"
}

echo -e "${YELLOW}Starting attack...${NC}"
echo "Position | Char | Instructions | Status"
echo "---------|------|-------------|--------"

for ((pos=0; pos<FLAG_LENGTH; pos++)); do
    best_char=""
    best_instructions=0
    declare -A char_results
    
    echo -e "${BLUE}Testing position $((pos+1))/$FLAG_LENGTH${NC}"
    
    for ((i=0; i<${#CHARSET}; i++)); do
        char="${CHARSET:$i:1}"
        instructions=$(test_character $pos "$char" "$found_flag")
        char_results["$char"]=$instructions
        
        printf "%8d | %4s | %11s | Testing\r" $((pos+1)) "$char" "$instructions"
        
        if [ "$instructions" -gt "$best_instructions" ] 2>/dev/null; then
            best_instructions=$instructions
            best_char="$char"
        fi
        
        echo "pos=$pos char=$char instructions=$instructions" >> "$results_file"
    done
    
    found_flag="$found_flag$best_char"
    
    echo -e "${GREEN}position $((pos+1)): Best char '$best_char' with $best_instructions instructions${NC}"
    echo -e "${YELLOW}curr flag: $found_flag${NC}"
    echo ""
    
    if [ ${#found_flag} -eq $FLAG_LENGTH ]; then
        echo -e "${GREEN}complete flag: $found_flag${NC}"
        final_test=$(test_character 0 "" "$found_flag")
        echo "final test: $final_test"
    fi
done

echo ""
echo -e "${GREEN}=== FINAL RESULT ===${NC}"
echo -e "${GREEN}flag: $found_flag${NC}"
echo ""
