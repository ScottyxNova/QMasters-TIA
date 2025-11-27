#!/bin/bash

# NPM Package Security Checker for Linux
# This script checks for vulnerable npm packages and sends results to a webhook

# Configuration
WEBHOOK_URL="WebHook_HERE_FOR_DATA"
# *** MODIFICATION: Updated to use the new package list format (package@version) ***
PACKAGE_LIST_PATH="./impacted_packages_with_versions.txt"
OUTPUT_FORMAT="json"  # Can be "json" or "csv"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --webhook)
            WEBHOOK_URL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --format [json|csv]    Output format (default: json)"
            echo "  --webhook URL          Webhook URL (default: configured)"
            echo "  --help                 Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    local no_newline=$3
    
    if [ "$no_newline" = "true" ]; then
        echo -en "${color}${message}${NC}"
    else
        echo -e "${color}${message}${NC}"
    fi
}

# Function to check if npm is installed
check_npm_installed() {
    if ! command-v npm &> /dev/null; then
        print_color "$RED" "ERROR: npm is not installed or not in PATH"
        print_color "$YELLOW" "Please install Node.js and npm before running this script."
        exit 1
    fi
}

# Function to get installed npm packages
get_installed_packages() {
    local scope=$1
    local scope_flag=""
    
    if [ "$scope" = "global" ]; then
        scope_flag="-g"
    fi
    
    local output=$(npm list $scope_flag --depth=0 --json 2>/dev/null)
    
    if [ $? -ne 0 ] || [ -z "$output" ]; then
        return
    fi
    
    echo "$output" | jq -r --arg scope "$scope" '
        .dependencies // {} | 
        to_entries[] | 
        {
            name: .key, 
            version: .value.version, 
            scope: $scope
        } | 
        @json'
}

# Function to send data to webhook
send_webhook_data() {
    local payload=$1
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local backup_file="./webhook_backup_$(date +%Y%m%d_%H%M%S).$OUTPUT_FORMAT"
    
    print_color "$CYAN" "\nSending data to webhook..."
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1)
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ] || [ "$http_code" = "202" ]; then
        print_color "$GREEN" "Successfully sent data to webhook!"
        return 0
    else
        print_color "$RED" "ERROR: Failed to send data to webhook (HTTP $http_code)"
        print_color "$YELLOW" "Saving data locally to: $backup_file"
        
        if [ "$OUTPUT_FORMAT" = "json" ]; then
            echo "$payload" | jq '.' > "$backup_file" 2>/dev/null || echo "$payload" > "$backup_file"
        else
            echo "$payload" > "$backup_file"
        fi
        
        return 1
    fi
}

# Function to convert packages to CSV format
packages_to_csv() {
    local packages=$1
    
    echo "PackageName,Version,Scope,Status,DetectedAt,Hostname,Username"
    echo "$packages" | jq -r '.[] | [
        .PackageName,
        .Version,
        .Scope,
        .Status,
        .DetectedAt,
        .Hostname,
        .Username
    ] | @csv'
}

# Main script execution
print_color "$CYAN" "\n========================================"
print_color "$CYAN" "  NPM Package Security Checker"
print_color "$CYAN" "========================================\n"

# Check if jq is installed
if ! command-v jq &> /dev/null; then
    print_color "$RED" "ERROR: jq is not installed"
    print_color "$YELLOW" "Please install jq: sudo apt-get install jq (Debian/Ubuntu) or sudo yum install jq (RedHat/CentOS)"
    exit 1
fi

# Check if npm is installed
check_npm_installed

# Check if input file exists
if [ ! -f "$PACKAGE_LIST_PATH" ]; then
    print_color "$RED" "ERROR: Package list file not found: $PACKAGE_LIST_PATH"
    exit 1
fi

# Read impacted packages (now in package@version format)
print_color "$WHITE" "Reading impacted packages from: $PACKAGE_LIST_PATH"
mapfile -t impacted_packages < <(grep -v '^[[:space:]]*$' "$PACKAGE_LIST_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

if [ ${#impacted_packages[@]} -eq 0 ]; then
    print_color "$YELLOW" "Warning: No packages found in the input file.\n"
    exit 0
fi

print_color "$WHITE" "Found ${#impacted_packages[@]} package(s) to check\n"

# Get installed packages (both global and local)
print_color "$WHITE" "Retrieving globally installed npm packages..."
global_packages=$(get_installed_packages "global")

print_color "$WHITE" "Retrieving locally installed npm packages..."
local_packages=$(get_installed_packages "local")

# Combine all packages
all_packages=$(echo -e "$global_packages\n$local_packages" | grep -v '^$')

if [ -z "$all_packages" ]; then
    print_color "$YELLOW" "Warning: No npm packages found installed on this system.\n"
    exit 0
fi

global_count=$(echo "$global_packages" | grep -c '^{' || echo "0")
local_count=$(echo "$local_packages" | grep -c '^{' || echo "0")
total_count=$((global_count + local_count))

print_color "$WHITE" "Total installed packages: $total_count (Global: $global_count, Local: $local_count)\n"

# Check for impacted packages
print_color "$CYAN" "Checking for impacted packages...\n"

found_packages=()
not_found_count=0
current_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
hostname=$(hostname)
username=$(whoami)

for package_version in "${impacted_packages[@]}"; do
    package_version=$(echo "$package_version" | xargs)  # Trim whitespace
    
    if [ -z "$package_version" ]; then
        continue
    fi
    
    # Split package@version into package_name and required_version
    package_name=$(echo "$package_version" | cut -d '@' -f 1)
    required_version=$(echo "$package_version" | cut -d '@' -f 2)
    
    print_color "$GRAY" "  Checking: " true
    print_color "$WHITE" "$package_name@$required_version" true
    
    # *** MODIFICATION: Search for matching packages by name AND version ***
    # The jq filter now checks both .name and .version
    matched=$(echo "$all_packages" | jq -r \
        --arg pkg_name "$package_name" \
        --arg req_ver "$required_version" \
        'select(.name == $pkg_name and .version == $req_ver)')
    
    if [ -n "$matched" ]; then
        print_color "$RED" " [FOUND]"
        
        # Process each match (should only be one since we match on version)
        while IFS= read -r match; do
            if [ -n "$match" ]; then
                pkg_name=$(echo "$match" | jq -r '.name')
                pkg_version=$(echo "$match" | jq -r '.version')
                pkg_scope=$(echo "$match" | jq -r '.scope')
                
                found_packages+=("{
                    \"PackageName\": \"$pkg_name\",
                    \"Version\": \"$pkg_version\",
                    \"Scope\": \"$pkg_scope\",
                    \"Status\": \"Vulnerable\",
                    \"DetectedAt\": \"$current_time\",
                    \"Hostname\": \"$hostname\",
                    \"Username\": \"$username\"
                }")
            fi
        done <<< "$matched"
    else
        print_color "$GREEN" " [Not Found]"
        ((not_found_count++))
    fi
done

# Prepare found packages JSON array
found_count=${#found_packages[@]}
packages_json="[]"
if [ $found_count -gt 0 ]; then
    packages_json="[$(IFS=,; echo "${found_packages[*]}")]"
fi

# Summary
print_color "$CYAN" "\n========================================"
print_color "$CYAN" "  Summary"
print_color "$CYAN" "========================================"
print_color "$WHITE" "Total packages checked: ${#impacted_packages[@]}"

if [ $found_count -gt 0 ]; then
    print_color "$RED" "Impacted packages found: $found_count"
else
    print_color "$GREEN" "Impacted packages found: $found_count"
fi

print_color "$GREEN" "Packages not found: $not_found_count"

# Display found packages
if [ $found_count -gt 0 ]; then
    print_color "$RED" "\nIMPACTED PACKAGES DETECTED:"
    echo "$packages_json" | jq -r '.[] | "  - \(.PackageName) v\(.Version) [\(.Scope)]"' | while read -r line; do
        print_color "$YELLOW" "$line"
    done
    
    print_color "$RED" "\nACTION REQUIRED: Please update or remove the impacted packages.\n"
else
    print_color "$GREEN" "\nGood news! No impacted packages found on this system.\n"
fi

# Prepare webhook payload
if [ "$OUTPUT_FORMAT" = "csv" ]; then
    csv_data=$(packages_to_csv "$packages_json")
    payload=$(jq -n \
        --arg timestamp "$current_time" \
        --arg hostname "$hostname" \
        --arg username "$username" \
        --arg total "${#impacted_packages[@]}" \
        --arg found "$found_count" \
        --arg notfound "$not_found_count" \
        --arg format "$OUTPUT_FORMAT" \
        --arg packages "$csv_data" \
        '{
            timestamp: $timestamp,
            hostname: $hostname,
            username: $username,
            totalPackagesChecked: ($total | tonumber),
            impactedPackagesFound: ($found | tonumber),
            packagesNotFound: ($notfound | tonumber),
            format: $format,
            packages: $packages
        }')
else
    payload=$(jq -n \
        --arg timestamp "$current_time" \
        --arg hostname "$hostname" \
        --arg username "$username" \
        --arg total "${#impacted_packages[@]}" \
        --arg found "$found_count" \
        --arg notfound "$not_found_count" \
        --arg format "$OUTPUT_FORMAT" \
        --argjson packages "$packages_json" \
        '{
            timestamp: $timestamp,
            hostname: $hostname,
            username: $username,
            totalPackagesChecked: ($total | tonumber),
            impactedPackagesFound: ($found | tonumber),
            packagesNotFound: ($notfound | tonumber),
            format: $format,
            packages: $packages
        }')
fi

# Send data to webhook
if send_webhook_data "$payload"; then
    print_color "$GREEN" "\nData successfully transmitted to monitoring system."
else
    print_color "$YELLOW" "\nWarning: Data transmission failed but results are saved locally."
fi

print_color "$CYAN" "\nScript execution completed.\n"

# Exit with appropriate code
if [ $found_count -gt 0 ]; then
    exit 1
else
    exit 0
fi
