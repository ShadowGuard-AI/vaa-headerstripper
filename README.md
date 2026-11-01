# vaa-HeaderStripper
Reports what an HTTP response header listing would look like with the named headers removed from the listing. Nothing is removed from the target server, from its responses, or from any proxy: the target still sends every header to every visitor. Use the listing to see which headers a response carries and which ones you may want to configure the server itself to stop sending.

The tool fetches headers from the operator named URL with `requests`. Headers are reported for every response the server returns, including error status responses, with the status code noted. Only a connection level failure exits non-zero without a listing.

Values of credential shaped headers are masked in stdout and in the `-o` file: Set-Cookie, Cookie, Authorization, Proxy-Authorization, X-Api-Key, and any header whose name contains auth, cookie, or token is shown as [REDACTED], with the header name still listed.

## Install
`git clone https://github.com/ShadowGuard-AI/vaa-headerstripper`

## Usage
`python3 main.py URL [-H HEADER ...] [-o OUTPUT] [--force] [-v]`

## Parameters
- `url`: The target URL to fetch headers from.
- `-h`: Show help message and exit
- `-H`: A list of headers to remove from the listing. Defaults to Server, X-Powered-By, and X-AspNet-Version.
- `-o`: Output file to save the header listing. An existing file is refused unless `--force` is given.
- `--force`: Allow `-o` to overwrite an existing file.
- `-v`: Enable verbose output for debugging.

## License
Copyright (c) ShadowGuardAI
