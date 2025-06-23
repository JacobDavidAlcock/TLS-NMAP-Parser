#!/usr/bin/gawk -f

# AWK Script to Parse and Group Nmap ssl-enum-ciphers Output
#
# Version 5.1
#
# This script processes Nmap's ssl-enum-ciphers output and extracts:
#   1. Hosts supporting deprecated protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1).
#   2. Hosts supporting weak ciphers (strength rating less than 'A').
#
# The output format for both findings can be switched between a consolidated
# summary (default) and a detailed, grouped list (via command-line flag).
#
# Usage:
#   Default (Consolidated Lists for Protocols & Ciphers):
#     ./parse_tls.awk nmap_output.txt
#
#   Grouped by Protocol & Host (Detailed View):
#     gawk -v group=1 -f parse_tls.awk nmap_output.txt
#
# Note: This script uses features of GNU Awk (gawk), such as 'asorti'.

# This function prints a list of items in a formatted, multi-column layout.
# The number of columns is determined by the total number of items.
function print_hosts(hosts,    sorted_hosts, count, cols, i) {
    count = asorti(hosts, sorted_hosts)
    if (count == 0) {
        return
    }

    # Determine the number of columns based on the host count.
    if (count > 30) {
        cols = 3
    } else if (count > 10) {
        cols = 2
    } else {
        cols = 1
    }

    # Loop through the sorted hosts and print them in formatted columns.
    for (i = 1; i <= count; i++) {
        printf "    %-30s", sorted_hosts[i]
        if (i % cols == 0) {
            printf "\n"
        }
    }

    # Add a final newline if the last row was not completely filled.
    if (count % cols != 0) {
        printf "\n"
    }
}

# This function creates a separator line (e.g., "----") of a given length.
function print_separator(len,    i, line) {
    line = ""
    for (i = 0; i < len; i++) {
        line = line "-"
    }
    print line
}

# This function is called when a new Nmap report starts.
function reset_state() {
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
/^\|\s+SSLv2:/ {
    found_sslv2[ip ":" port] = 1
}
/^\|\s+SSLv3:/ {
    found_sslv3[ip ":" port] = 1
}
/^\|\s+TLSv1\.0:/ {
    found_tls10[ip ":" port] = 1
}
/^\|\s+TLSv1\.1:/ {
    found_tls11[ip ":" port] = 1
}

# Store unique weak ciphers for each host:port
/ciphers:/, /compressors:/ {
    if (NF >= 3 && $(NF-1) == "-" && $NF != "A" && $NF != "experimental") {
        cipher_name = $2
        unique_weak_ciphers[ip ":" port, cipher_name] = 1
    }
}

# At the very end of the file, process and print all collected results.
END {
    # --- Print Protocols Section ---
    print "==========================================="
    print "FINDING: DEPRECATED SSL/TLS PROTOCOLS ENABLED"
    print "===========================================\n"

    # Check if any deprecated protocols were found at all.
    if (length(found_sslv2) == 0 && length(found_sslv3) == 0 && length(found_tls10) == 0 && length(found_tls11) == 0) {
        print "No hosts with deprecated protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) found.\n"
    } else {
        # The 'group' variable is passed from the command line, e.g., gawk -v group=1
        if (group) {
            # --- GROUPED PROTOCOL MODE ---
            if (length(found_sslv2) > 0) {
                print "Affected Protocol: SSLv2"
                print_separator(24)
                print_hosts(found_sslv2)
                print ""
            }
            if (length(found_sslv3) > 0) {
                print "Affected Protocol: SSLv3"
                print_separator(24)
                print_hosts(found_sslv3)
                print ""
            }
            if (length(found_tls10) > 0) {
                print "Affected Protocol: TLSv1.0"
                print_separator(26)
                print_hosts(found_tls10)
                print ""
            }
            if (length(found_tls11) > 0) {
                print "Affected Protocol: TLSv1.1"
                print_separator(26)
                print_hosts(found_tls11)
                print ""
            }
        } else {
            # --- CONSOLIDATED PROTOCOL MODE (DEFAULT) ---
            # 1. Collect all unique hosts into a single list
            # Guard each loop with a length check to prevent fatal error on empty (scalar) variables.
            if (length(found_sslv2) > 0) for (host_port in found_sslv2) all_deprecated_hosts[host_port] = 1
            if (length(found_sslv3) > 0) for (host_port in found_sslv3) all_deprecated_hosts[host_port] = 1
            if (length(found_tls10) > 0) for (host_port in found_tls10) all_deprecated_hosts[host_port] = 1
            if (length(found_tls11) > 0) for (host_port in found_tls11) all_deprecated_hosts[host_port] = 1

            # 2. Build the combined protocol string
            protocol_list = ""
            if (length(found_sslv2) > 0) {
                protocol_list = protocol_list (protocol_list ? " & " : "") "SSLv2"
            }
            if (length(found_sslv3) > 0) {
                protocol_list = protocol_list (protocol_list ? " & " : "") "SSLv3"
            }
            if (length(found_tls10) > 0) {
                protocol_list = protocol_list (protocol_list ? " & " : "") "TLSv1.0"
            }
            if (length(found_tls11) > 0) {
                protocol_list = protocol_list (protocol_list ? " & " : "") "TLSv1.1"
            }
            header = "Affected Protocols: " protocol_list
            print header
            print_separator(length(header))

            # 3. Print all affected hosts together
            print_hosts(all_deprecated_hosts)
            print ""
        }
    }

    # --- Process Ciphers Data ---
    # This loop populates data structures for both grouped and consolidated modes.
    for (key in unique_weak_ciphers) {
        split(key, parts, SUBSEP)
        host_port = parts[1]
        cipher = parts[2]

        # For grouped mode: associate ciphers with their specific host
        grouped_ciphers[host_port] = grouped_ciphers[host_port] "    (" cipher ")\n"

        # For consolidated mode: collect all unique ciphers and affected hosts
        all_weak_ciphers[cipher] = 1
        all_cipher_hosts[host_port] = 1
    }

    # --- Print Ciphers Section ---
    print "======================================="
    print "FINDING: WEAK TLS CIPHERS ENABLED"
    print "=======================================\n"

    if (length(all_weak_ciphers) > 0) {
        if (group) {
            # --- GROUPED CIPHER MODE ---
            asorti(grouped_ciphers, sorted_hosts)
            for (i=1; i<=length(sorted_hosts); i++) {
                host_port = sorted_hosts[i]
                printf "%s:\n%s\n", host_port, grouped_ciphers[host_port]
            }
        } else {
            # --- CONSOLIDATED CIPHER MODE (DEFAULT) ---
            # 1. Print all unique weak ciphers
            print "Affected Ciphers:"
            print_separator(17)
            asorti(all_weak_ciphers, sorted_ciphers)
            for (i=1; i<=length(sorted_ciphers); i++) {
                print "    " sorted_ciphers[i]
            }
            print ""

            # 2. Print all affected hosts
            print "Affected Hosts:"
            print_separator(15)
            print_hosts(all_cipher_hosts)
            print ""
        }
    } else {
        print "No hosts with weak ciphers (strength less than A) found."
    }
}
