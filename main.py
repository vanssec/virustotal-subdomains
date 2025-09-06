import json
import re
from urllib.parse import urlparse

def get_virustotal_urls(domain, api_key):
    # Construct the VirusTotal API URL
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
    
    try:
        # Make the API request
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        # Parse the JSON response
        data = response.json()
        
        # Check if the response code indicates success
        if data.get("response_code") != 1:
            return ["Error: Domain not found in VirusTotal dataset"]
        
        # Convert the entire JSON response to a string
        response_text = json.dumps(data)
        
        # Define regex pattern for URLs (http, https, and ftp)
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*?(?=\s|$|[^\w./?=&-])'
        
        # Find all URLs in the response text
        urls = set(re.findall(url_pattern, response_text))
        
        # Add subdomains as URLs
        for subdomain in data.get("subdomains", []):
            urls.add(f"https://{subdomain}")
        
        # Remove any empty strings and sort the URLs
        urls = sorted([url for url in urls if url and is_valid_url(url, domain)])
        
        # Save URLs to a file named virustotal_<domain>.txt
        filename = f"virustotal_{domain}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(url + '\n')
        
        return urls
    
    except requests.exceptions.HTTPError as http_err:
        return [f"HTTP Error: {http_err}"]
    except requests.exceptions.RequestException as req_err:
        return [f"Request Error: {req_err}"]
    except ValueError as json_err:
        return [f"JSON Parsing Error: {json_err}"]
    except IOError as io_err:
        return [f"File Error: Could not write to {filename}: {io_err}"]

def is_valid_url(url, domain):
    """Check if the URL belongs to the specified domain or its subdomains."""
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc.lower()
        domain = domain.lower()
        return netloc == domain or netloc.endswith(f".{domain}")
    except ValueError:
        return False

def main():
    # Get user input
    domain = input("Enter the domain to scan (e.g., example.com): ").strip()
    api_key = input("Enter your VirusTotal API key: ").strip()
    
    # Fetch URLs
    urls = get_virustotal_urls(domain, api_key)
    
    # Print results
    if urls and urls[0].startswith("Error"):
        print(urls[0])
    elif urls:
        print(f"\nURLs found for {domain}:\n")
        for url in urls:
            print(url)
        print(f"\nTotal URLs found: {len(urls)}")
        print(f"URLs saved to virustotal_{domain}.txt")
    else:
        print(f"No URLs found for {domain}")

if __name__ == "__main__":
    main()
