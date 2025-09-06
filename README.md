# VirusTotal URL Fetcher

A Python script to **fetch** and **save** URLs associated with a given domain from the [VirusTotal API](https://www.virustotal.com/), including subdomains and URLs found in the API response, with _robust error handling_ and domain validation.

## ✨ **Features**

- **Fetches URLs** from VirusTotal's domain report, including subdomains and embedded URLs.
- **Extracts URLs** using a regex pattern for `http`, `https`, and `ftp` links.
- **Validates URLs** to ensure they belong to the specified domain or its subdomains.
- **Saves results** to a text file (`virustotal_<domain>.txt`) for easy access.
- **Handles errors gracefully**:
  - HTTP errors, request issues, JSON parsing errors, and file I/O issues.
  - Checks for invalid API responses (e.g., domain not found).

## 🛠 **Requirements**

- **Python 3.6+**
- Required packages:
  - `requests`
  - `urllib3` (included with `requests`)
- A **VirusTotal API key** (obtain from [VirusTotal](https://www.virustotal.com/)).

Install dependencies using:

```bash
pip install requests
```

To ensure compatibility, update dependencies if needed:

```bash
pip install --upgrade requests urllib3
```

## 🚀 **Usage**

1. Clone or download the script.
2. Run the script and provide a domain and your VirusTotal API key when prompted:

```bash
python virustotal_url_fetcher.py
```

3. Enter a domain (e.g., `example.com`) and your API key.
4. The script will:
   - Query the VirusTotal API for the domain's report.
   - Extract and validate URLs and subdomains.
   - Save valid URLs to `virustotal_<domain>.txt`.
   - Display the URLs found, total count, and confirmation of file saving.

### 📋 **Example**

```bash
$ python virustotal_url_fetcher.py
Enter the domain to scan (e.g., example.com): example.com
Enter your VirusTotal API key: your_api_key_here
URLs found for example.com:

https://example.com
https://sub1.example.com
https://sub2.example.com
...

Total URLs found: 3
URLs saved to virustotal_example.com.txt
```

## 🔍 **Code Overview**

- **Main Function**: Prompts for a domain and API key, then orchestrates the URL fetching process.
- **Fetch Function** (`get_virustotal_urls`):
  - Queries the VirusTotal API with the provided domain and API key.
  - Extracts URLs using a regex pattern and adds subdomains as `https://` URLs.
  - Validates URLs to match the domain or its subdomains using `urlparse`.
  - Saves results to a text file and returns the sorted list of URLs.
- **Validation Function** (`is_valid_url`):
  - Checks if a URL belongs to the specified domain or its subdomains.
- **Error Handling**:
  - Handles HTTP errors, request issues, JSON parsing errors, and file I/O errors.
  - Returns descriptive error messages for issues like invalid API keys or missing domains.

## 📝 **Notes**

> [!NOTE]  
> **API Key**: You need a valid VirusTotal API key. Free keys have rate limits, so consider a premium key for heavy usage.

> [!TIP]  
> Use a specific domain (e.g., `example.com`) to ensure accurate results and avoid irrelevant URLs.

> [!CAUTION]  
> Ensure your API key is kept _secure_ and not shared publicly, as it can be misused.

- **Rate Limits**: VirusTotal’s API has rate limits, especially for free accounts, which may cause delays or errors.
- **Output File**: Results are saved as `virustotal_<domain>.txt` in the script’s directory.
- **URL Validation**: Only URLs matching the domain or its subdomains are included to avoid irrelevant results.

## 📜 **License**

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
