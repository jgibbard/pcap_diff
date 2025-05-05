#pragma once

#include <string>
#include <vector>

#include <packets.h>

namespace PcapWriter {

  enum class Mode{Basic, Full, MatchA, MatchB, Added, Removed};

  void WritePcap(const std::string& filename, const Packets& packets_a,
                 const Packets& packets_b, const std::string& mode);

  void WritePcapMatched(const std::string& filename,
                        const Packets& packets, bool matched);

  void WritePcapBasic(const std::string& filename,
                      const Packets& packets_a,
                      const Packets& packets_b);

  void WritePcapFull(const std::string& filename,
                     const Packets& packets_a,
                     const Packets& packets_b);

  Mode StringToMode(const std::string& mode);

  void CopyHeaderIncLen(uint8_t* file, PcapFile::PacketHeader header, 
                        uint32_t inc = 1);
  
  uint8_t* WritePacketFullFormat(uint8_t* file_ptr, const Packet& packet,
                                 uint32_t link_layer, bool added);
  uint8_t* WritePacketFullFormatMatch(uint8_t* file_ptr, const Packet& packet,
                                      uint32_t link_layer_a,
                                      uint32_t link_layer_b);
} 