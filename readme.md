# Nmap TLS Weakness Parser

An `awk` script designed to parse the output of Nmap's `ssl-enum-ciphers` script and generate a clean, organized report detailing hosts with weak TLS configurations.

This tool is intended for penetration testers and system administrators to quickly consolidate scan data into a human-readable format suitable for reporting and remediation tracking. It identifies hosts supporting deprecated protocols (TLSv1.0/1.1) and those offering weak cipher suites (strength less than 'A').

## Features

- **Automated Parsing**: Processes large Nmap output files in a single pass.
- **Intelligent Grouping**: Automatically categorizes vulnerable hosts based on the type of TLS protocol weakness (TLSv1.0 only, TLSv1.1 only, or both).
- **Weak Cipher Identification**: Extracts and lists all unique cipher suites with a strength rating below 'A' for each service.
- **Report-Ready Output**: Formats the findings with clear headings, sorted lists, and columns for easy inclusion in a technical report.
- **Handles FQDNs & IPs**: Correctly parses the host identifier whether it's a direct IP or a hostname with the IP in parentheses.

## Workflow

The process involves two main steps:

1. Run a specific Nmap scan to generate the raw data.
2. Run this `awk` script to parse the raw data into a clean report.

## Prerequisites

- `nmap`: Network scanning tool with SSL enumeration capabilities
- `awk`: Text processing utility (available on most Unix-like systems)

## Installation & Usage

### Step 1: Generate Nmap Scan Data

This script is designed to parse the specific output from Nmap's `ssl-enum-ciphers` script. You must run a scan similar to the one below to generate a compatible input file.

**Example Nmap Command:**

```bash
# Create a file named 'ip.txt' with your target IP addresses, one per line.
# Then run the following command:
nmap -sV --script ssl-enum-ciphers -p 443,3389,636,3269,5986 -iL ip.txt > crypt.txt
```

- You can add or remove ports from the `-p` flag as needed.
- The output must be saved to a file (e.g., `crypt.txt`).

### Step 2: Parse the Output

Once your Nmap scan is complete and you have the `crypt.txt` file, use the `parse_tls.awk` script to generate your report.

#### 1. Make the script executable:

```bash
chmod +x parse_tls.awk
```

#### 2. Run the script:

```bash
./parse_tls.awk crypt.txt
```

#### 3. (Optional) Save the formatted report to a file:

```bash
./parse_tls.awk crypt.txt > weak_tls_report.md
```

## Sample Output

The script will produce a clearly formatted output like this:

```
===========================================
FINDING: DEPRECATED TLS PROTOCOLS ENABLED
===========================================

[HIGH] Hosts supporting BOTH TLSv1.0 and TLSv1.1:
------------------------------------------------
    192.168.1.1:636         192.168.1.2:3389

[MEDIUM] Hosts supporting ONLY TLSv1.0:
--------------------------------------
    192.168.1.2:443

=======================================
FINDING: DEPRECATED TLS CIPHERS ENABLED
=======================================

192.168.1.1:443:
    (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    (TLS_RSA_WITH_RC4_128_SHA)

192.168.1.2:3389:
    (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
```

## Understanding the Output

### TLS Protocol Findings

- **HIGH**: Hosts supporting both TLSv1.0 and TLSv1.1 (most vulnerable)
- **MEDIUM**: Hosts supporting only TLSv1.0 or TLSv1.1

### Cipher Suite Findings

The script identifies cipher suites with strength ratings below 'A', which typically include:

- Weak encryption algorithms (RC4, 3DES)
- Cipher suites vulnerable to known attacks
- Deprecated cryptographic methods

## Common TLS Vulnerabilities Detected

This tool helps identify systems vulnerable to:

- **BEAST Attack**: Exploits TLS 1.0 CBC cipher vulnerability
- **POODLE Attack**: Affects systems falling back to SSL 3.0
- **RC4 Attacks**: Multiple vulnerabilities in RC4 cipher
- **Sweet32 Attack**: Exploits 3DES cipher weaknesses

## Customization

You can modify the script to:

- Change the strength threshold for cipher identification
- Adjust output formatting
- Add additional categorization rules
- Include or exclude specific cipher patterns

## Troubleshooting

### Common Issues

- **No output generated**: Ensure your Nmap scan used the `ssl-enum-ciphers` script
- **Parsing errors**: Verify the input file format matches expected Nmap output
- **Missing hosts**: Check that your Nmap scan completed successfully for all targets

### Verifying Input Format

The script expects Nmap output in this format:

```
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.0:
|     ciphers:
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
```

## Disclaimer

This tool is intended for use in authorized security testing and network administration scenarios only. The user is responsible for ensuring they have explicit, written permission to test any targets.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest enhancements through the GitHub issue tracker.
