#!/usr/bin/env bash

###############################################################################
# region_check.sh
#
# This script:
#   - Accepts a parameter --region=<region>.
#   - Downloads the corresponding domains_<region>.txt from the same GitHub repo.
#   - Performs parallel ping/HTTPS/SSL checks with colored output.
#
# Repository: https://github.com/lillink13/domain-checker
# Date: 2025-02-01
###############################################################################

# -----------------------------------------------------------------------------
# 1) Set the base "raw" URL of your GitHub repo.
#    Adjust if you change branches or directory structure.
# -----------------------------------------------------------------------------
REPO_BASE="https://raw.githubusercontent.com/lillink13/domain-checker/main"

# -----------------------------------------------------------------------------
# 2) Parse command-line arguments for --region
# -----------------------------------------------------------------------------
REGION=""
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
    *)
      echo "Unknown argument: $1"
      echo "Usage: $0 --region <region_name>"
      exit 1
      ;;
  esac
done

if [[ -z "$REGION" ]]; then
  echo "Error: you must specify --region <region>, e.g.: --region=rus"
  exit 1
fi

# -----------------------------------------------------------------------------
# 3) Clear the console before proceeding
# -----------------------------------------------------------------------------
clear

# -----------------------------------------------------------------------------
# 4) Download the appropriate domain file from the repo
#    e.g., domains_rus.txt, domains_eu.txt, etc.
# -----------------------------------------------------------------------------
DOMAIN_FILE_NAME="domains_${REGION}.txt"
TEMP_FILE="/tmp/domains_${REGION}_$$.txt"

echo "Fetching domain list for region '${REGION}' from GitHub repo..."
curl -sL "${REPO_BASE}/${DOMAIN_FILE_NAME}" -o "$TEMP_FILE"

# Check if the domain file was downloaded
if [[ ! -s "$TEMP_FILE" ]]; then
  echo "Error: could not download '${DOMAIN_FILE_NAME}'."
  echo "Please ensure the file exists in the repo or the region is correct."
  exit 1
fi

# -----------------------------------------------------------------------------
# 5) Now we insert the logic from a colored, parallel domain check script
#    (like your domain_check_parallel_colored.sh), but we replace references
#    to the local 'domains.txt' with $TEMP_FILE.
# -----------------------------------------------------------------------------

# ASCII-art banner (you can change or remove it as needed)
echo -e "\033[95m"  # magenta color for banner
cat <<'EOF'
           (`-').->   (`-')      _  (`-')  _     <-. (`-')_                          (`-').-> (`-')  _          <-.(`-')  (`-')  _   (`-')  
           ( OO)_  <-.(OO )      \-.(OO ) (_)       \( OO) )    .->        _         (OO )__  ( OO).-/ _         __( OO)  ( OO).-/<-.(OO )  
 .--. .--.(_)--\_) ,------,)     _.'    \ ,-(`-'),--./ ,--/  ,---(`-')     \-,-----.,--. ,'-'(,------. \-,-----.'-'. ,--.(,------.,------,) 
/_  |/_  |/    _ / |   /`. '    (_...--'' | ( OO)|   \ |  | '  .-(OO )      |  .--./|  | |  | |  .---'  |  .--./|  .'   / |  .---'|   /`. ' 
 |  | |  |\_..`--. |  |_.' |    |  |_.' | |  |  )|  . '|  |)|  | .-, \     /_) (`-')|  `-'  |(|  '--.  /_) (`-')|      /)(|  '--. |  |_.' | 
 |  | |  |.-._)   \|  .   .'    |  .___.'(|  |_/ |  |\    | |  | '.(_/     ||  |OO )|  .-.  | |  .--'  ||  |OO )|  .   '  |  .--' |  .   .' 
 |  | |  |\       /|  |\  \     |  |      |  |'->|  | \   | |  '-'  |     (_'  '--'\|  | |  | |  `---.(_'  '--'\|  |\   \ |  `---.|  |\  \  
 `--' `--' `-----' `--' '--'    `--'      `--'   `--'  `--'  `-----'         `-----'`--' `--' `------'   `-----'`--' '--' `------'`--' '--'
EOF
echo -e "\033[0m\n"

echo "Starting domain checks for region: $REGION"
sleep 1

# -- Define color constants and arrays
COLOR_RESET="\033[0m"
COLOR_PROGRESS="\033[96m"    # cyan for progress bar

COLOR_GRADIENT=(
  "\033[92m"         # 0: bright green
  "\033[32m"         # 1: green
  "\033[33m"         # 2: yellow
  "\033[93m"         # 3: bright yellow
  "\033[38;5;208m"   # 4: orange
  "\033[38;5;214m"   # 5: brighter orange
  "\033[31m"         # 6: red
  "\033[91m"         # 7: bright red
  "\033[38;5;196m"   # 8: even brighter red
  "\033[38;5;197m"   # 9: near-pinkish red
)

# -- print_progress_bar
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

# -- get_ping_avg
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

# -- check_ssl_valid
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

# -- check_https_redirects
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

# -- check_domain
check_domain() {
  local domain="$1"

  # 1) Base ping
  local base_ping_avg
  base_ping_avg=$(get_ping_avg "$domain" 2)
  if [[ -z "$base_ping_avg" ]]; then
    echo "${domain};;N/A;N/A;PING_UNREACH"
    return
  fi

  local base_ping_float
  base_ping_float=$(awk -v v="$base_ping_avg" 'BEGIN{print v+0}')

  # If > 20 ms => "PING_EXCEEDS"
  if (( $(awk -v val="$base_ping_float" 'BEGIN{print (val>20)?1:0}') )); then
    echo "${domain};${base_ping_float};N/A;N/A;PING_EXCEEDS"
    return
  fi

  # 2) Refine ping
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
    return
  fi

  # 4) SSL check
  local ssl_label="SSL_Valid"
  if ! check_ssl_valid "$domain"; then
    ssl_label="SSL_Invalid"
    echo "${domain};${final_ping};${ssl_label};${final_url};SSL_ERROR"
    return
  fi

  echo "${domain};${final_ping};${ssl_label};${final_url};OK"
}

# Main logic now: use $TEMP_FILE as the domain list
FILE_WITH_DOMAINS="$TEMP_FILE"
TOTAL_DOMAINS=$(grep -E '^[^#[:space:]]' "$FILE_WITH_DOMAINS" | wc -l)
if [[ $TOTAL_DOMAINS -eq 0 ]]; then
  echo "No valid domains found in '$FILE_WITH_DOMAINS'."
  rm -f "$TEMP_FILE"
  exit 0
fi

RESULTS_FILE="/tmp/results_${REGION}_$$.tmp"
rm -f "$RESULTS_FILE"
touch "$RESULTS_FILE"

# Export for xargs
export -f get_ping_avg
export -f check_ssl_valid
export -f check_https_redirects
export -f check_domain

# Parallel check with xargs
grep -E '^[^#[:space:]]' "$FILE_WITH_DOMAINS" | \
  xargs -I{} -P 4 bash -c 'check_domain "$@"' _ {} >> "$RESULTS_FILE" &

XARGS_PID=$!

# Show progress bar
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

# If no lines => no results
if [[ ! -s "$RESULTS_FILE" ]]; then
  echo "No results produced (all domains may have failed)."
  rm -f "$TEMP_FILE"
  exit 0
fi

# Sort by ping (numeric), pushing 'N/A' or huge pings to the bottom
awk '
BEGIN { FS=OFS=";" }
{
  if ($2 ~ /^[0-9.]+$/) {
    # numeric => keep as is
  } else {
    $2 = 999999
  }
  print $0
}' "$RESULTS_FILE" | sort -t';' -k2n > sorted.tmp

TOTAL_RESULTS=$(wc -l < sorted.tmp)
mapfile -t ALL_LINES < sorted.tmp

echo -e "Final Results (sorted by ping) for region '${REGION}':"
echo -e "=============================================================="
header_color="\033[1m\033[4m" # bold + underline
printf "${header_color}%-20s %-10s %-12s %-30s${COLOR_RESET}\n" "Domain" "Ping(ms)" "SSL" "Final_URL"

pick_color_for_rank() {
  local idx=$1
  local total=$2
  local rank_percent=$(( idx * 100 / total ))
  local bucket=$(( rank_percent / 10 ))
  (( bucket < 0 )) && bucket=0
  (( bucket > 9 )) && bucket=9
  echo -ne "${COLOR_GRADIENT[$bucket]}"
}

for i in "${!ALL_LINES[@]}"; do
  line="${ALL_LINES[$i]}"
  domain=$(echo "$line" | cut -d';' -f1)
  pingv=$(echo "$line" | cut -d';' -f2)
  sslv=$(echo "$line" | cut -d';' -f3)
  finalurl=$(echo "$line" | cut -d';' -f4)
  status=$(echo "$line" | cut -d';' -f5)

  # If status != OK => bright red
  if [[ "$status" != "OK" ]]; then
    row_color="\033[91m"
  else
    row_color=$(pick_color_for_rank "$i" "$TOTAL_RESULTS")
  fi

  # Adjust ping if it's 999999
  if (( $(awk -v val="$pingv" 'BEGIN{print (val>99998)?1:0}') )); then
    if [[ "$status" == "PING_EXCEEDS" ]]; then
      pingv=">20ms"
    elif [[ "$status" == "PING_UNREACH" ]]; then
      pingv="unreach"
    else
      pingv="N/A"
    fi
  fi

  if [[ "$status" == "HTTPS_ERROR" || "$status" == "PING_UNREACH" ]]; then
    finalurl="N/A"
    sslv="N/A"
  elif [[ "$status" == "SSL_ERROR" ]]; then
    :
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
echo "Done. Results above."

# Cleanup
rm -f "$TEMP_FILE" "$RESULTS_FILE" sorted.tmp
