#pragma once
#include <cstdint>
#include <vector>
#include <pcap_file.h>


struct Packet {
    struct PcapFile::PacketHeader header;
    std::vector<uint8_t> data;
    bool match;
    const Packet* match_packet;
};