#!/usr/bin/awk -f

# AWK Script to Parse and Group Nmap ssl-enum-ciphers Output
#
# This script processes the output from Nmap's ssl-enum-ciphers script and
# extracts two categories of findings:
#   1. Hosts supporting deprecated protocols, grouped and formatted for reporting.
#   2. Hosts supporting weak ciphers (strength rating less than 'A'), with duplicates removed.
#
# Usage:
# 1. Save this script as, e.g., parse_tls.awk
# 2. Make it executable: chmod +x parse_tls.awk
# 3. Run it against your Nmap output file: ./parse_tls.awk crypt.txt

# This function is called when a new Nmap report starts to reset our variables.
function reset_state() {
    # Extract IP address, handling FQDNs like "host.com (1.2.3.4)"
    ip = $NF
    gsub(/[()]/, "", ip)
    port = "N/A"
}

# When a line starts with "Nmap scan report for", a new host block begins.
/^Nmap scan report for/ {
    reset_state()
}

# When a line contains a port that is open, capture the port number.
/^[0-9]+\/tcp\s+open/ {
    split($1, port_arr, "/")
    port = port_arr[1]
}

# Store flags for which weak protocols are seen for a given host:port
/^\|\s+TLSv1\.0:/ {
    found_tls10[ip ":" port] = 1
}
/^\|\s+TLSv1\.1:/ {
    found_tls11[ip ":" port] = 1
}

# Store unique weak ciphers for each host:port
/ciphers:/, /compressors:/ {
    if (NF >= 3 && $(NF-1) == "-" && $NF != "A" && $NF != "experimental") {
        # Extract just the cipher name (the second field)
        cipher_name = $2
        
        # Use a compound key to track unique ciphers per host:port.
        # This automatically handles duplicates.
        unique_weak_ciphers[ip ":" port, cipher_name] = 1
    }
}

# At the very end of the file, process and print all collected results.
END {
    # --- Process and Group Protocols ---
    # Create arrays for each category based on the flags we set.
    for (host_port in found_tls10) {
        if (host_port in found_tls11) {
            both_hosts[host_port] = 1
        } else {
            only_tls10_hosts[host_port] = 1
        }
    }
    # Find hosts that only support TLSv1.1
    for (host_port in found_tls11) {
        if (!(host_port in found_tls10)) {
            only_tls11_hosts[host_port] = 1
        }
    }

    # --- Print Grouped Protocols ---
    print "==========================================="
    print "FINDING: DEPRECATED TLS PROTOCOLS ENABLED"
    print "===========================================\n"
    
    # Group 1: Both TLSv1.0 and TLSv1.1
    print "[HIGH] Hosts supporting BOTH TLSv1.0 and TLSv1.1:"
    print "------------------------------------------------"
    if (length(both_hosts) > 0) {
        asorti(both_hosts, sorted_hosts) # Sort the hosts alphabetically
        for (i=1; i<=length(sorted_hosts); i++) {
             printf "    %-25s", sorted_hosts[i] # Print in formatted columns
             if (i % 3 == 0) printf "\n" # Create 3 columns
        }
        if (length(sorted_hosts) % 3 != 0) printf "\n"
    } else {
        print "    None found."
    }
    print ""

    # Group 2: TLSv1.0 Only
    print "[MEDIUM] Hosts supporting ONLY TLSv1.0:"
    print "--------------------------------------"
    if (length(only_tls10_hosts) > 0) {
        asorti(only_tls10_hosts, sorted_hosts)
        for (i=1; i<=length(sorted_hosts); i++) {
             printf "    %-25s", sorted_hosts[i]
             if (i % 3 == 0) printf "\n"
        }
        if (length(sorted_hosts) % 3 != 0) printf "\n"
    } else {
        print "    None found."
    }
    print ""

    # Group 3: TLSv1.1 Only
    print "[MEDIUM] Hosts supporting ONLY TLSv1.1:"
    print "--------------------------------------"
    if (length(only_tls11_hosts) > 0) {
        asorti(only_tls11_hosts, sorted_hosts)
        for (i=1; i<=length(sorted_hosts); i++) {
             printf "    %-25s", sorted_hosts[i]
             if (i % 3 == 0) printf "\n"
        }
        if (length(sorted_hosts) % 3 != 0) printf "\n"
    } else {
        print "    None found."
    }
    print "\n"

    # --- Process and Group Ciphers ---
    # Invert the unique_weak_ciphers array for easy, grouped printing.
    for (key in unique_weak_ciphers) {
        split(key, parts, SUBSEP)
        host_port = parts[1]
        cipher = parts[2]
        
        grouped_ciphers[host_port] = grouped_ciphers[host_port] "    (" cipher ")\n"
    }

    # --- Print Grouped Ciphers ---
    print "======================================="
    print "FINDING: DEPRECATED TLS CIPHERS ENABLED"
    print "=======================================\n"
    
    if (length(grouped_ciphers) > 0) {
        # Sort the host:port combinations for consistent output
        asorti(grouped_ciphers, sorted_hosts)
        for (i=1; i<=length(sorted_hosts); i++) {
            host_port = sorted_hosts[i]
            # Updated printf statement for cleaner output
            printf "%s:\n%s\n", host_port, grouped_ciphers[host_port]
        }
    } else {
        print "No hosts with weak ciphers (strength less than A) found."
    }
}
