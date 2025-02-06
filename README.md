## Description

**region_check.sh** is a Bash script that fetches a list of domains for a specified region from a GitHub repository and performs parallel checks on each domain:

- **Ping** response and average latency
- **HTTPS** redirection check
- **SSL** certificate validity

The script then displays the results in color-coded form (based on latency) and supports saving the output to a `.txt` or `.json` file. It can also log detailed information (if the `--verbose` flag is used).

## How to Use

**Example usage** (curl command to download this script directly from GitHub):

```bash
bash <(curl -sL https://raw.githubusercontent.com/lillink13/domain-checker/main/region_check.sh) --region eu
```

## Flags

- `--region=<region>` **REQUIRED**  
    **Example:** `--region=eu`  
    Specifies the region whose domain list you want to check. This parameter is required.
    
    **Supported Regions:**
    
    - `eu` (European Union)
    
    **WIP (Work in Progress) Regions:**
    
    - `us` (United States)
	- `rus` (Russia)
    - `cn` (China)
    
    **Queue (Planned) Regions:**
	- `au` (Australia)
	 
- `--l <en|ru>`  
    **Example:** `--l en`  
    Sets the language of script messages. Use `en` for English (default) or `ru` for Russian.
    
- `--s <txt|json>`  
    **Example:** `--s json`  
    Saves the final results to a file in `.txt` or `.json` format.
    
- `--v` or `--verbose`  
    **Example:** `--v`  
    Enables detailed logging to a log file (`.log`). Useful for debugging or detailed reports.
    