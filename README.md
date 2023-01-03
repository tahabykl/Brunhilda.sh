# Brunhilda.sh
Brunhilda is an automated tool for web application reconnaissance and security audits.

## Features

- Fuzzing: Attempt to find hidden directories and files on a target domain.
- Permutating: Take a wordlist and permutate it to find hidden directories and files.
- Screenshotting: Take screenshots of target domains.
- HTTPx blacklisting: Exclude certain subdomains from being tested.
- Gau integration: Use Gau to gather subdomains.
- JavaScript scanning: Use Dalfox to scan for JavaScript vulnerabilities.
- Automatic updates: Check for updates to the script on every run.

## Usage

```bash
./Brunhilda.sh [-f|--fuzz] [-p|--permutate] [-s|--screenshot] [-hb|--httpx-blacklist <file>] [-g|--gau] [-j|--javascript] [-d|--dalfox] [-o|--override] [-t|--threads <number>] [-v|--verbose] [-h|--help] <domain list file>
```

## Example Usage

```bash
./Brunhilda.sh -fpst 20 -gjd targets.txt
```
