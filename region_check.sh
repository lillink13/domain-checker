#!/usr/bin/env bash

###############################################################################
# region_check.sh
#
# This script:
#   - Accepts parameters:
#       --region=<region>
#       --l <en|ru>         (language: en = English, ru = Russian)
#       --s <txt|json>      (save results to file in txt or json format)
#       --v or --verbose    (enable detailed logging to a log file)
#
#   - Downloads the corresponding domains_<region>.txt from the GitHub repo.
#   - Performs parallel ping/HTTPS/SSL checks with colored output.
#
# Repository: https://github.com/lillink13/domain-checker
# Updated: 2025-02-06
###############################################################################

# ==================== Version and Basic Variables ====================
VERSION="1.1.3"
LANGUAGE="en"    # Default language is English (use --l ru for Russian)
SAVE_FORMAT=""   # Format to save results: txt or json (via --s option)
VERBOSE=0        # Verbose logging flag (via --v or --verbose)

# ------------------ Command-Line Arguments Parsing --------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)
      REGION="$2"
      shift 2
      ;;
    --region=*)
      REGION="${1#*=}"
      shift 1
      ;;
    --l)
      LANGUAGE="$2"
      shift 2
      ;;
    --l=*)
      LANGUAGE="${1#*=}"
      shift 1
      ;;
    --s)
      SAVE_FORMAT="$2"
      shift 2
      ;;
    --s=*)
      SAVE_FORMAT="${1#*=}"
      shift 1
      ;;
    --v|--verbose)
      VERBOSE=1
      shift 1
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: $0 --region <region> [--l <en|ru>] [--s <txt|json>] [--v|--verbose]"
      exit 1
      ;;
  esac
done

# Check for required region parameter
if [[ -z "$REGION" ]]; then
  if [[ "$LANGUAGE" == "ru" ]]; then
    echo "Ошибка: необходимо указать --region <region>, например: --region=ru"
  else
    echo "Error: you must specify --region <region>, e.g.: --region=ru"
  fi
  exit 1
fi

# Force English if language is not Russian
if [[ "$LANGUAGE" != "ru" ]]; then
  LANGUAGE="en"
fi

# ------------------ Set Message Texts Based on Language -------------------------
if [[ "$LANGUAGE" == "ru" ]]; then
    MSG_VERSION="Версия программы: %s\n"
    MSG_FETCHING="Получение списка доменов для региона '%s' из репозитория GitHub..."
    MSG_ERROR_DOWNLOAD="Ошибка: не удалось загрузить '%s'.\nУбедитесь, что файл существует в репозитории или регион указан неверно."
    MSG_START_CHECK="Запуск проверки доменов для региона: %s"
    MSG_NO_VALID_DOMAINS="В файле '%s' не найдено корректных доменов."
    MSG_FINAL_RESULTS="Итоговые результаты (отсортированы по пингу) для региона '%s':"
    MSG_DONE="Done. Results above."
else
    MSG_VERSION="Program version: %s\n"
    MSG_FETCHING="Fetching domain list for region '%s' from GitHub repo..."
    MSG_ERROR_DOWNLOAD="Error: could not download '%s'.\nPlease ensure the file exists in the repo or the region is correct."
    MSG_START_CHECK="Starting domain checks for region: %s"
    MSG_NO_VALID_DOMAINS="No valid domains found in '%s'."
    MSG_FINAL_RESULTS="Final Results (sorted by ping) for region '%s':"
    MSG_DONE="Готово. Результаты выше."
fi

# ------------------- Initialize Logging if Verbose is Enabled ------------
if [[ "$VERBOSE" -eq 1 ]]; then
   LOG_FILE="domain_checker_${REGION}_$(date +%Y%m%d_%H%M%S).log"
   echo "Logging enabled. Log file: $LOG_FILE"
   echo "[$(date +'%Y-%m-%d %H:%M:%S')] Program started. Version: $VERSION, Region: $REGION, Language: $LANGUAGE, Save Format: $SAVE_FORMAT" > "$LOG_FILE"
fi

# Function to log messages if verbose logging is enabled
log_message() {
   if [[ "$VERBOSE" -eq 1 ]]; then
      echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
   fi
}
export -f log_message

# ------------------- Clear the Console and Print Version --------------------------
if [[ -t 1 ]]; then
  # Clear the screen
  echo -en "\033[2J\033[H"
fi

# Print program version
printf "$MSG_VERSION" "$VERSION"
log_message "Console cleared and version printed."

# ----------------------- Main Script Logic -----------------------------

# 1) Set the base "raw" URL of your GitHub repo.
REPO_BASE="https://raw.githubusercontent.com/lillink13/domain-checker/main"

# 2) Download the appropriate domain file from the repo
DOMAIN_FILE_NAME="domains_${REGION}.txt"
TEMP_FILE="/tmp/domains_${REGION}_$$.txt"

printf "\n$MSG_FETCHING\n" "$REGION"
log_message "Fetching domain list for region: $REGION"
curl -sL "${REPO_BASE}/${DOMAIN_FILE_NAME}" -o "$TEMP_FILE"

# Check if the domain file was downloaded
if [[ ! -s "$TEMP_FILE" ]]; then
  printf "$MSG_ERROR_DOWNLOAD\n" "$DOMAIN_FILE_NAME"
  log_message "Failed to download domain file: $DOMAIN_FILE_NAME"
  exit 1
fi

# 3) ASCII-art banner
echo -e "\033[95m"  # Set magenta color for banner
cat <<'EOF'
         (`-').->  (`-')      _  (`-') _    <-. (`-')_                        (`-').->(`-')  _        <-.(`-') (`-')  _  (`-')  
         ( OO)_ <-.(OO )      \-.(OO )(_)      \( OO) )   .->        _        (OO )__ ( OO).-/_        __( OO) ( OO).-<-.(OO )  
 .--..--(_)--\_),------,)     _.'    \,-(`-',--./ ,--/ ,---(`-')     \-,-----,--. ,'-(,------.\-,-----'-'. ,--(,------,------,) 
/_  /_  /    _ /|   /`. '    (_...--''| ( OO|   \ |  |'  .-(OO )      |  .--.|  | |  ||  .---' |  .--.|  .'   /|  .---|   /`. ' 
 |  ||  \_..`--.|  |_.' |    |  |_.' ||  |  |  . '|  ||  | .-, \     /_) (`-'|  `-'  (|  '--. /_) (`-'|      /(|  '--.|  |_.' | 
 |  ||  .-._)   |  .   .'    |  .___.(|  |_/|  |\    ||  | '.(_/     ||  |OO |  .-.  ||  .--' ||  |OO |  .   ' |  .--'|  .   .' 
 |  ||  \       |  |\  \     |  |     |  |'-|  | \   ||  '-'  |     (_'  '--'|  | |  ||  `---(_'  '--'|  |\   \|  `---|  |\  \  
 `--'`--'`-----'`--' '--'    `--'     `--'  `--'  `--' `-----'         `-----`--' `--'`------'  `-----`--' '--'`------`--' '--' 
EOF
echo -e "\033[0m\n"
log_message "Banner displayed."

# 4) Starting domain checks
printf "$MSG_START_CHECK\n" "$REGION"
log_message "Starting domain checks for region: $REGION"
sleep 1

# ----------------------- Color Constants and Arrays -----------------------
COLOR_RESET="\033[0m"
COLOR_PROGRESS="\033[96m"    # Cyan for progress bar

COLOR_GRADIENT=(
  "\033[92m"         # Bright green
  "\033[32m"         # Green
  "\033[33m"         # Yellow
  "\033[93m"         # Bright yellow
  "\033[38;5;208m"   # Orange
  "\033[38;5;214m"   # Lighter orange
  "\033[31m"         # Red
  "\033[91m"         # Bright red
  "\033[38;5;196m"   # Even brighter red
  "\033[38;5;197m"   # Near-pinkish red
)

# ----------------------- Function Definitions ---------------------

# Function to print the progress bar
print_progress_bar() {
  local progress=$1
  local width=${2:-30}
  local filled=$((progress * width / 100))
  local empty=$((width - filled))

  echo -ne "${COLOR_PROGRESS}["
  for ((i=0; i<filled; i++)); do
    echo -n "#"
  done
  for ((i=0; i<empty; i++)); do
    echo -n "."
  done
  echo -ne "] ${progress}%${COLOR_RESET}"
}

# Function to get the average ping for a domain
get_ping_avg() {
  local domain="$1"
  local count="$2"
  local output
  output=$(ping -c "$count" -w 3 "$domain" 2>/dev/null)
  [[ -z "$output" ]] && echo "" && return

  local avg
  avg=$(echo "$output" | sed -n 's/.*rtt min\/avg\/max\/mdev = [^\/]*\/\([^\/]*\)\/.*/\1/p')
  if [[ -z "$avg" ]]; then
    avg=$(echo "$output" | sed -n 's/.*round-trip min\/avg\/max\/stddev = [^\/]*\/\([^\/]*\)\/.*/\1/p')
  fi
  echo "$avg"
}

# Function to check the validity of SSL certificate
check_ssl_valid() {
  local domain="$1"
  local ssl_info
  ssl_info=$(echo |
    openssl s_client -connect "${domain}:443" -servername "$domain" 2>/dev/null |
    openssl x509 -noout -dates 2>/dev/null
  )
  [[ -z "$ssl_info" ]] && return 1

  local not_after
  not_after=$(echo "$ssl_info" | grep "notAfter=" | sed 's/notAfter=//')
  [[ -z "$not_after" ]] && return 1

  local end_ts
  end_ts=$(date -d "$not_after" +%s 2>/dev/null)
  if [[ -z "$end_ts" ]]; then
    end_ts=$(date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null)
  fi
  [[ -z "$end_ts" ]] && return 1

  local now_ts
  now_ts=$(date +%s)
  (( end_ts > now_ts ))
}

# Function to check HTTPS redirects
check_https_redirects() {
  local domain="$1"
  local final_url
  final_url=$(curl -s -I -L --max-redirs 10 -o /dev/null -w "%{url_effective}" "https://${domain}")
  [[ -z "$final_url" ]] && echo "" && return

  if [[ "$final_url" == "https://${domain}" ]]; then
    if ! curl -s --head --max-redirs 0 "https://${domain}" &>/dev/null; then
      echo ""
      return
    fi
  fi
  echo "$final_url"
}

# Main function to check a domain
check_domain() {
  local domain="$1"
  log_message "Starting check for domain: $domain"

  # 1) Basic ping
  local base_ping_avg
  base_ping_avg=$(get_ping_avg "$domain" 2)
  log_message "Domain: $domain, base ping: $base_ping_avg"
  if [[ -z "$base_ping_avg" ]]; then
    echo "${domain};;N/A;N/A;PING_UNREACH"
    log_message "Domain $domain unreachable (no ping response)."
    return
  fi

  local base_ping_float
  base_ping_float=$(awk -v v="$base_ping_avg" 'BEGIN{print v+0}')

  # If ping > 20 ms => PING_EXCEEDS
  if (( $(awk -v val="$base_ping_float" 'BEGIN{print (val>20)?1:0}') )); then
    echo "${domain};${base_ping_float};N/A;N/A;PING_EXCEEDS"
    log_message "Domain $domain: ping $base_ping_float > 20ms (PING_EXCEEDS)."
    return
  fi

  # 2) Refined ping measurement
  local final_ping="$base_ping_float"
  if (( $(awk -v val="$base_ping_float" 'BEGIN{print (val > 10 && val <= 20)?1:0}') )); then
    local t
    t=$(get_ping_avg "$domain" 4)
    [[ -n "$t" ]] && final_ping="$t"
  elif (( $(awk -v val="$base_ping_float" 'BEGIN{print (val > 5 && val <= 10)?1:0}') )); then
    local t
    t=$(get_ping_avg "$domain" 6)
    [[ -n "$t" ]] && final_ping="$t"
  elif (( $(awk -v val="$base_ping_float" 'BEGIN{print (val >= 0 && val <= 5)?1:0}') )); then
    local t
    t=$(get_ping_avg "$domain" 8)
    [[ -n "$t" ]] && final_ping="$t"
  fi

  # 3) HTTPS check
  local final_url
  final_url=$(check_https_redirects "$domain")
  if [[ -z "$final_url" ]]; then
    echo "${domain};${final_ping};N/A;N/A;HTTPS_ERROR"
    log_message "Domain $domain: HTTPS error."
    return
  fi

  # 4) SSL check
  local ssl_label="SSL_Valid"
  if ! check_ssl_valid "$domain"; then
    ssl_label="SSL_Invalid"
    echo "${domain};${final_ping};${ssl_label};${final_url};SSL_ERROR"
    log_message "Domain $domain: SSL error."
    return
  fi

  echo "${domain};${final_ping};${ssl_label};${final_url};OK"
  log_message "Domain $domain checked successfully: ping=$final_ping, ssl=$ssl_label."
}

# Get the list of domains from the temporary file
FILE_WITH_DOMAINS="$TEMP_FILE"
TOTAL_DOMAINS=$(grep -E '^[^#[:space:]]' "$FILE_WITH_DOMAINS" | wc -l)
if [[ $TOTAL_DOMAINS -eq 0 ]]; then
  printf "$MSG_NO_VALID_DOMAINS\n" "$FILE_WITH_DOMAINS"
  log_message "No valid domains found in $FILE_WITH_DOMAINS."
  rm -f "$TEMP_FILE"
  exit 0
fi

RESULTS_FILE="/tmp/results_${REGION}_$$.tmp"
rm -f "$RESULTS_FILE"
touch "$RESULTS_FILE"

# Export functions for use by parallel processes
export -f get_ping_avg
export -f check_ssl_valid
export -f check_https_redirects
export -f check_domain

# Parallel domain check using xargs
grep -E '^[^#[:space:]]' "$FILE_WITH_DOMAINS" | \
  xargs -I{} -P 4 bash -c 'check_domain "$@"' _ {} >> "$RESULTS_FILE" &

XARGS_PID=$!

# Display progress bar
while kill -0 "$XARGS_PID" 2>/dev/null; do
  processed=$(wc -l < "$RESULTS_FILE")
  perc=$(( processed * 100 / TOTAL_DOMAINS ))
  echo -ne "\rProgress: "
  print_progress_bar "$perc" 30
  sleep 1
done

processed=$(wc -l < "$RESULTS_FILE")
perc=$(( processed * 100 / TOTAL_DOMAINS ))
echo -ne "\rProgress: "
print_progress_bar "$perc" 30
echo -e "  ... Done!\n"
log_message "Domain checking completed. Processed $processed out of $TOTAL_DOMAINS domains."

# If no results were produced, exit
if [[ ! -s "$RESULTS_FILE" ]]; then
  echo "No results produced (all domains may have failed)."
  log_message "No results produced; exiting."
  rm -f "$TEMP_FILE"
  exit 0
fi

# Sort the results by ping (numeric sorting; non-numeric pings are pushed to the bottom)
awk '
BEGIN { FS=OFS=";" }
{
  if ($2 ~ /^[0-9.]+$/) {
    # Leave numeric values as is
  } else {
    $2 = 999999
  }
  print $0
}' "$RESULTS_FILE" | sort -t';' -k2n > sorted.tmp

TOTAL_RESULTS=$(wc -l < sorted.tmp)
mapfile -t ALL_LINES < sorted.tmp

printf "\n$MSG_FINAL_RESULTS\n" "$REGION"
echo "=============================================================="
header_color="\033[1m\033[4m"  # Bold and underlined header
printf "${header_color}%-20s %-10s %-12s %-30s${COLOR_RESET}\n" "Domain" "Ping(ms)" "SSL" "Final_URL"

# Function to pick a color based on ranking by ping
pick_color_for_rank() {
  local idx=$1
  local total=$2
  local rank_percent=$(( idx * 100 / total ))
  local bucket=$(( rank_percent / 10 ))
  (( bucket < 0 )) && bucket=0
  (( bucket > 9 )) && bucket=9
  echo -ne "${COLOR_GRADIENT[$bucket]}"
}

# Print results with color coding
for i in "${!ALL_LINES[@]}"; do
  line="${ALL_LINES[$i]}"
  domain=$(echo "$line" | cut -d';' -f1)
  pingv=$(echo "$line" | cut -d';' -f2)
  sslv=$(echo "$line" | cut -d';' -f3)
  finalurl=$(echo "$line" | cut -d';' -f4)
  status=$(echo "$line" | cut -d';' -f5)

  # Use bright red if status is not OK
  if [[ "$status" != "OK" ]]; then
    row_color="\033[91m"
  else
    row_color=$(pick_color_for_rank "$i" "$TOTAL_RESULTS")
  fi

  # Adjust ping value if it is set to 999999
  if (( $(awk -v val="$pingv" 'BEGIN{print (val>99998)?1:0}') )); then
    if [[ "$status" == "PING_EXCEEDS" ]]; then
      pingv=">20ms"
    elif [[ "$status" == "PING_UNREACH" ]]; then
      pingv="unreach"
    else
      pingv="N/A"
    fi
  fi

  printf "%b%-20s %-10s %-12s %-30s%b\n" \
    "$row_color" \
    "$domain" \
    "$pingv" \
    "$sslv" \
    "$finalurl" \
    "$COLOR_RESET"
done

echo "=============================================================="
echo "$MSG_DONE"
log_message "Final results printed to console."

# --------- Save Results to a File (txt or json) ---------
if [[ -n "$SAVE_FORMAT" ]]; then
   OUTPUT_FILE="results_${REGION}_$(date +%Y%m%d_%H%M%S).${SAVE_FORMAT}"
   if [[ "$SAVE_FORMAT" == "txt" ]]; then
      {
         printf "%-20s %-10s %-12s %-30s %-15s\n" "Domain" "Ping(ms)" "SSL" "Final_URL" "Status"
         printf '%.0s-' {1..90}
         echo
         while IFS=';' read -r domain pingv sslv finalurl status; do
            if (( $(awk -v val="$pingv" 'BEGIN{print (val>99998)?1:0}') )); then
              if [[ "$status" == "PING_EXCEEDS" ]]; then
                pingv=">20ms"
              elif [[ "$status" == "PING_UNREACH" ]]; then
                pingv="unreach"
              else
                pingv="N/A"
              fi
            fi
            printf "%-20s %-10s %-12s %-30s %-15s\n" "$domain" "$pingv" "$sslv" "$finalurl" "$status"
         done < sorted.tmp
      } > "$OUTPUT_FILE"
      echo "Results saved to $OUTPUT_FILE"
      log_message "Results saved to file: $OUTPUT_FILE"
   elif [[ "$SAVE_FORMAT" == "json" ]]; then
      {
         echo "["
         first=1
         while IFS=';' read -r domain pingv sslv finalurl status; do
            if (( $(awk -v val="$pingv" 'BEGIN{print (val>99998)?1:0}') )); then
              if [[ "$status" == "PING_EXCEEDS" ]]; then
                pingv=">20ms"
              elif [[ "$status" == "PING_UNREACH" ]]; then
                pingv="unreach"
              else
                pingv="N/A"
              fi
            fi
            if [ $first -eq 0 ]; then
               echo "  ,"
            fi
            printf "  {\"domain\": \"%s\", \"ping\": \"%s\", \"ssl\": \"%s\", \"final_url\": \"%s\", \"status\": \"%s\"}" \
              "$domain" "$pingv" "$sslv" "$finalurl" "$status"
            first=0
         done < sorted.tmp
         echo
         echo "]"
      } > "$OUTPUT_FILE"
      echo "Results saved to $OUTPUT_FILE"
      log_message "Results saved to file: $OUTPUT_FILE"
   else
      echo "Unknown save format: $SAVE_FORMAT. Supported formats: txt, json."
      log_message "Unknown save format specified: $SAVE_FORMAT"
   fi
fi

# Final logging and cleanup
log_message "Script finished. Cleaning up temporary files."

# Cleanup temporary files
rm -f "$TEMP_FILE" "$RESULTS_FILE" sorted.tmp
