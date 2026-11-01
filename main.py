import argparse
import requests
import logging
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='vaa-HeaderStripper: Reports what a response header listing would look like with named headers removed from the listing. Nothing is removed from the target server or its responses.')
    parser.add_argument('url', help='The target URL to scan.')
    parser.add_argument('-H', '--headers', nargs='+', default=['Server', 'X-Powered-By', 'X-AspNet-Version'],
                        help='A list of headers to strip. Defaults to Server, X-Powered-By, and X-AspNet-Version.')
    parser.add_argument('-o', '--output', help='Output file to save the header listing. An existing file is not overwritten unless --force is given.', default=None)
    parser.add_argument('--force', action='store_true', help='Allow -o to overwrite an existing file.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging.')
    return parser

def validate_url(url):
    """
    Validates the given URL to ensure it is well-formed.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme and netloc
    except:
        return False

def fetch_headers(url):
    """
    Fetches the HTTP response headers from the specified URL.

    Args:
        url (str): The URL to fetch headers from.

    Returns:
        dict: A dictionary containing the HTTP response headers.
        None: If there is an error fetching the headers.
    """
    try:
        with requests.get(url, stream=True, timeout=10) as response:
            logging.info(f"Response status: {response.status_code}")
            print(f"Status: {response.status_code}")
            return dict(response.headers)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching headers from {url}: {e}")
        return None

def sanitize_headers(headers, headers_to_strip):
    """
    Removes specified headers from the given header dictionary.

    Args:
        headers (dict): A dictionary of HTTP headers.
        headers_to_strip (list): A list of header names to remove.

    Returns:
        dict: A new dictionary with the specified headers removed.
    """
    sanitized_headers = dict(headers)
    for header in headers_to_strip:
        for key in list(sanitized_headers):
            if key.lower() == header.lower():
                del sanitized_headers[key]
                logging.info(f"Removed from listing: {header}")
    return sanitized_headers

CREDENTIAL_HEADERS = {"set-cookie", "authorization", "cookie", "x-api-key", "x-custom-auth", "proxy-authorization"}

def display_value(name, value):
    lowered = name.lower()
    if lowered in CREDENTIAL_HEADERS or "auth" in lowered or "cookie" in lowered or "api-key" in lowered or "token" in lowered:
        return "[REDACTED]"
    return value

def save_headers_to_file(headers, filename, force=False):
    """
    Saves the headers to a file.

    Args:
        headers (dict): The dictionary of headers to save.
        filename (str): The name of the file to save the headers to.
    """
    import os
    if os.path.exists(filename) and not force:
        logging.error(f"Output file already exists and will not be overwritten without --force: {filename}")
        return False
    try:
        with open(filename, 'w') as f:
            for key, value in headers.items():
                f.write(f"{key}: {display_value(key, value)}\n")
        logging.info(f"Headers saved to file: {filename}")
        return True
    except IOError as e:
        logging.error(f"Error saving headers to file {filename}: {e}")
        return False

def main():
    """
    Main function to execute the header stripping process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not validate_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL including scheme (http/https).")
        sys.exit(1)

    logging.info(f"Target URL: {args.url}")
    logging.info(f"Headers to strip: {args.headers}")

    headers = fetch_headers(args.url)
    if headers is None:
        sys.exit(1)

    sanitized_headers = sanitize_headers(headers, args.headers)

    print("\nHeaders with named headers removed from this listing (the target still sends them):")
    for key, value in sanitized_headers.items():
        print(f"{key}: {display_value(key, value)}")

    if args.output:
        if not save_headers_to_file(sanitized_headers, args.output, force=args.force):
            sys.exit(1)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic usage: python vaa_headerstripper.py http://example.com
# 2. Strip specific headers: python vaa_headerstripper.py http://example.com -H Server X-Powered-By
# 3. Save output to file: python vaa_headerstripper.py http://example.com -o sanitized_headers.txt
# 4. Enable verbose output: python vaa_headerstripper.py http://example.com -v