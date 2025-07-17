# vaa-HeaderStripper
Removes potentially sensitive information from HTTP response headers based on a configurable list of headers to strip. Uses `requests` to fetch the headers and provides command-line options to specify target URLs and headers to sanitize. - Focused on Automates basic vulnerability assessment tasks, like scanning website headers, checking for common CMS vulnerabilities (using public CVE databases), and identifying outdated software versions. Aims to provide a quick initial security check.

## Install
`git clone https://github.com/ShadowGuardAI/vaa-headerstripper`

## Usage
`./vaa-headerstripper [params]`

## Parameters
- `-h`: Show help message and exit
- `-H`: A list of headers to strip. Defaults to Server, X-Powered-By, and X-AspNet-Version.
- `-o`: Output file to save sanitized headers.
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowGuardAI
