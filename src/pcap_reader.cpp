#include <stdexcept>
#include <cstring>
#include <pcap_reader.h>
#include <iostream>


PcapReader::PcapReader(const std::string& path)
    : pcap_file_(path), filename_(path) {

  // PCAP file must be at least as long as the main file header
  if (pcap_file_.Size() < sizeof(PcapFile::FileHeader)) {
    throw std::runtime_error("Failed to parse file: " + path + "\n"
                             "File is too small to be a PCAP file.");
  }
  // Copy over PCAP file header for easy access
  std::memcpy(&Header_, pcap_file_.Data(), sizeof(PcapFile::FileHeader));

  // PCAP Magic number is:
  // 0xA1B2C3D4: Microsecond timestamp (Supported)
  // 0xA1B23C4D: Nanoseconds timestamp (Not Supported)
  // 0xD4C3B2A1: Microsecond timestamp - Opposite endian (Not Supported)
  // 0x4D3CB2A1: Nanoseconds timestamp - Opposite endian (Not Supported)

  // Check the magic number is not the nanoseconds magic number.
  if (Header_.magic_number == 0xA1B23C4D) {
    throw std::runtime_error("Failed to parse file: " + path + "\n"
                              "PCAP file uses nanoseconds timestamps. "
                              "Only PCAPs with microseconds timestamps are "
                              "supported.");
  }
  // Check the PCAP is not using the opposite endian to the processor
  if (Header_.magic_number == 0xD4C3B2A1 ||
      Header_.magic_number == 0x4D3CB2A1) {
    throw std::runtime_error("Failed to parse file: " + path + "\n"
                              "PCAP file uses a different endian to this "
                              "processor. Only PCAPs with the same endian to "
                              "the processor running the program are "
                              "supported.");
  }
  // Check file is actually a PCAP file
  if (Header_.magic_number != 0xA1B2C3D4) {
    throw std::runtime_error("Failed to parse file: " + path + "\n"
                              "File is not a PCAP file.");
  }

  // Only PCAP version 2.4 is supported. This is the version used
  // by wireshark and tcpdump.
  if (Header_.major_version != 2 || Header_.minor_version != 4) {
    throw std::runtime_error("Failed to parse file: " + path + "\n"
                              "PCAP file version " +
                              std::to_string(Header_.major_version) + "." +
                              std::to_string(Header_.minor_version) + " "
                              "is not supported."
                              "Only version 2.4 is supported");
  }
}

std::vector<Packet> PcapReader::GetPackets(uint64_t max_packets) const {
  // Get a pointer to the first byte after the PCAP global header
  const uint8_t* packet_ptr = pcap_file_.Data() + sizeof(PcapFile::FileHeader);
  const uint8_t* end_ptr = pcap_file_.Data() + pcap_file_.Size();

  // We can't really reserve space as each packet has a variable length
  // TODO: We could estimate this off the file size and typical packet length
  std::vector<Packet> packets;

  // Loop through each packet header, read the size, and copy the header and 
  // data into a vector.
  while (packet_ptr + sizeof(PcapFile::PacketHeader) <= end_ptr) {
    const auto* header_ptr = \
        reinterpret_cast<const PcapFile::PacketHeader*>(packet_ptr);

    if (header_ptr->incl_len != header_ptr->orig_len) {
      throw std::runtime_error("Failed to parse file: " + filename_ + "\n"
                               "Packet " + std::to_string(packets.size()) +
                               " was truncated. Comparing PCAPs with truncated"
                               " data captures is not supported.");
    }

    packet_ptr += sizeof(PcapFile::PacketHeader);

    if (packet_ptr + header_ptr->incl_len > end_ptr) {
      throw std::runtime_error("Failed to parse file: " + filename_ + "\n"
                               "File appears truncated or corrupt.");
    }
    // Construct the header and data directly in the packets vector
    // This should avoid unneeded copying / moving initially.
    // Since the size of the vector will keep growing, it will likely be
    // moved several times.
    packets.emplace_back(Packet{*header_ptr, std::vector<uint8_t>(
        packet_ptr, packet_ptr+header_ptr->incl_len), false, nullptr});

    packet_ptr += header_ptr->incl_len;

    // Allow the user to only load the first packet_counter packets
    if (max_packets != 0 && packets.size() == max_packets) {
      break;
    }
  }

  // If we didn't limit the number of packets, then the packet_ptr
  // should be at the end of the file. If it isn't then something went wrong.
  if (max_packets == 0 && packet_ptr != end_ptr) {
    throw std::runtime_error("Failed to parse file: " + filename_ + "\n"
                             "File appears truncated or corrupt.");
  }

  if (packets.size() == 0) {
    throw std::runtime_error("Failed to parse file: " + filename_ + "\n"
      "File contains no packets.");
  }

  // Named return value optimisation will stop this being a copy operation
  return packets;
}

uint32_t PcapReader::GetLinkLayer() const {
  return Header_.link_type;
}