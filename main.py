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
    parser = argparse.ArgumentParser(description='vaa-HeaderStripper: Removes sensitive information from HTTP response headers.')
    parser.add_argument('url', help='The target URL to scan.')
    # Naming even one header with -H replaces this default list wholesale, it does not extend it. An operator who adds a custom header and forgets the defaults silently stops stripping Server, which is the header most runs exist to remove.
    parser.add_argument('-H', '--headers', nargs='+', default=['Server', 'X-Powered-By', 'X-AspNet-Version'],
                        help='A list of headers to strip. Defaults to Server, X-Powered-By, and X-AspNet-Version.')
    parser.add_argument('-o', '--output', help='Output file to save sanitized headers.', default=None)
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
        # Streaming with no body read and no close leaves the connection hanging on the response object until garbage collection. I only ever want the headers, but a HEAD request would have said so to the server; some servers answer GET and HEAD with different header sets, which is the tradeoff I accepted without noting it until now.
        response = requests.get(url, stream=True, timeout=10)  # Added timeout
        # An error status makes me discard the response entirely, headers included. A 404 page still carries a Server header worth stripping, but my run exits 1 in main and the operator sees nothing of it.
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.headers
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
    # Everything I strip is stripped from this local copy. The server keeps sending the real headers to everyone else; my output is a filtered view for a report or a proxy config, and anyone reading the tool name as a server side change is giving it credit it has not earned.
    sanitized_headers = headers.copy()
    for header in headers_to_strip:
        if header in sanitized_headers:
            del sanitized_headers[header]
            logging.info(f"Stripped header: {header}")
    return sanitized_headers

def save_headers_to_file(headers, filename):
    """
    Saves the headers to a file.

    Args:
        headers (dict): The dictionary of headers to save.
        filename (str): The name of the file to save the headers to.
    """
    try:
        with open(filename, 'w') as f:
            for key, value in headers.items():
                f.write(f"{key}: {value}\n")
        logging.info(f"Headers saved to file: {filename}")
    # As with the fetch path, a failed save only reaches the log. The sanitized list has already printed, the exit code stays 0, and the missing file is discoverable only by looking for it.
    except IOError as e:
        logging.error(f"Error saving headers to file {filename}: {e}")

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

    print("\nSanitized Headers:")
    for key, value in sanitized_headers.items():
        print(f"{key}: {value}")

    if args.output:
        save_headers_to_file(sanitized_headers, args.output)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic usage: python vaa_headerstripper.py http://example.com
# 2. Strip specific headers: python vaa_headerstripper.py http://example.com -H Server X-Powered-By
# 3. Save output to file: python vaa_headerstripper.py http://example.com -o sanitized_headers.txt
# 4. Enable verbose output: python vaa_headerstripper.py http://example.com -v