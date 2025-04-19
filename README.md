# PCAP Diff Tool
A tool to identify the differences between two PCAP files and display the result
in Wireshark.

Ideal for testing packet filtering, routing, and encapsulation.

## Features
- **Byte Mask:** Set which bytes are compared. Allows skipping TTL, Checksums,
                 Counters, etc.
- **Multi Link Layer:** Custom byte ranges for comparison. Allow's comparing
                        just the payload of two different carrier protocols.
- **PCAP Output:** Uses wireshark to view the results.
- **Multiple comparison modes:** Choose between a full search or a timestamp
                                 based window search.

## Basic Usage
```bash
pcap_diff <File A> <File B>
```
- Returns 0 if files match
- Returns 1 if files differ
- Returns 2 on error

## Building
```
g++ -O3 --std=c++11 -Wpedantic -Wextra -Wall -Werror -Wfatal-errors packets.cpp pcap_diff.cpp packet_diff.cpp mapped_file.cpp pcap_reader.cpp pcap_writer.cpp timestamp.cpp pcap_file.cpp -I./include -o pcap_diff
```

## Wireshark Colouring
When using the "basic" output mode, the following colouring option in
wireshark will highlight removed packets in red and added packets in 
green:
```
@Removed@frame[-1] == 0x01@[63222,24929,20817][0,0,0]
@Added@frame[-1] == 0x02@[36751,61680,42148][0,0,0]
```
