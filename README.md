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

### Prerequisites

I plan to create an installation script for Brunhilda in the future when I have some free time.

```bash
./Brunhilda.sh [-f|--fuzz] [-p|--permutate] [-s|--screenshot] [-hb|--httpx-blacklist <file>] [-g|--gau] [-j|--javascript] [-d|--dalfox] [-o|--override] [-t|--threads <number>] [-v|--verbose] [-h|--help] <domain list file>
```

## Example Usage



```bash
chmod+x Brunhilda.sh; mv Brunhilda.sh Brunhilda
./Brunhilda -fpst 20 -gjd targets.txt
```

## What to Expect

This is just yet another bash script to automate web app reconnaissance that we coded with [@Yigit](https://github.com/theFr1nge) in our free time, so don't expect too much from it. It was initially created as a simple script to help with our personal needs, and I am happy to share it with others who may find it useful.

## Contributing

This project is quite straightforward, so you should be able to easily locate and fix any bugs you encounter. If you do so, feel free to submit a pull request with your changes. If you are unable to fix the issue on your own, don't hesitate to open an issue for assistance.
