#pragma once
#include <string>
#include <vector>

#include <packet.h>
#include <mapped_file.h>
#include <pcap_file.h>


/**
 * @brief Class for reading PCAP files
 * 
 */
class PcapReader {
  public:
    PcapReader(const std::string& path);
    std::vector<Packet> GetPackets(uint64_t max_packets = 0) const;
    uint32_t GetLinkLayer() const;
  private:
    MappedFile pcap_file_;
    PcapFile::FileHeader Header_;
    std::string filename_;
};