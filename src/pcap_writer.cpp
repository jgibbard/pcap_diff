#include <cstring>
#include <stdexcept>

#include <pcap_writer.h>
#include <pcap_file.h>
#include <mapped_file.h>

void PcapWriter::WritePcap(const std::string& filename,
    const Packets& packets_a, const Packets& packets_b,
    const std::string& mode) {      

  switch(StringToMode(mode)) {
    case PcapWriter::Mode::MatchA:
      WritePcapMatched(filename, packets_a, true);
      break;
    case PcapWriter::Mode::MatchB: 
      WritePcapMatched(filename, packets_b, true);
      break;
    case PcapWriter::Mode::Removed: 
      WritePcapMatched(filename, packets_a, false);
      break;
    case PcapWriter::Mode::Added:
      WritePcapMatched(filename, packets_b, false);
      break;
    case PcapWriter::Mode::Basic:
      WritePcapBasic(filename, packets_a, packets_b);
      break;
    case PcapWriter::Mode::Full:
      throw std::runtime_error("Output format 'full' is "
                               "currently unsupported");
      break;
  }

}

void PcapWriter::WritePcapMatched(const std::string& filename,
                                  const Packets& packets, bool matched) {
  
  size_t total_bytes = sizeof(PcapFile::FileHeader);
  for (const Packet& packet : packets) {
    if (packet.match == matched) {
      total_bytes += packet.data.size();
      total_bytes += sizeof(PcapFile::PacketHeader);
    }
  }
  // Memory map a writable file with the right size to store the whole PCAP
  MappedFile output_file(filename, true, total_bytes);
  uint8_t* data = output_file.DataWritable();

  // Copy over the PCAP global file header
  PcapFile::FileHeader file_header = \
      PcapFile::GetStandardHeader(packets.GetLinkLayer());
  std::memcpy(data, &file_header, sizeof(PcapFile::FileHeader));
  data += sizeof(PcapFile::FileHeader);

  // Write the rest of the data
  for (const auto& packet : packets) {
    if (packet.match == matched) {
      std::memcpy(data, &packet.header, sizeof(PcapFile::PacketHeader));
      data += sizeof(PcapFile::PacketHeader);
      std::memcpy(data, packet.data.data(), packet.data.size());
      data += packet.data.size();
    }
  }

}

void PcapWriter::WritePcapBasic(const std::string& filename,
                                const Packets& packets_a,
                                const Packets& packets_b) {

  // Calculate the exact size that the generated will be
  size_t total_bytes = sizeof(PcapFile::FileHeader);
  // Matched and unmatched (removed) packets in file A
  for (const Packet& packet : packets_a) {
    total_bytes += packet.data.size();
    total_bytes += sizeof(PcapFile::PacketHeader);
    // Extra byte for diff output
    total_bytes++;
  }
  // Just unmatched (added) packets in file B
  for (const Packet& packet : packets_b) {
    if (!packet.match) {
      total_bytes += packet.data.size();
      total_bytes += sizeof(PcapFile::PacketHeader);
      // Extra byte for diff output
      total_bytes++;
    }
  }
  // Memory map a writable file with the right size to store the whole PCAP
  MappedFile output_file(filename, true, total_bytes);
  uint8_t* data = output_file.DataWritable();


  // Packets from A and B will be combined, so they must
  // have the same link layer.
  if (packets_a.GetLinkLayer() != packets_b.GetLinkLayer()) {
    throw std::runtime_error("Link layer of Packets A and B differs. "
                             "The 'basic' output format requires that "
                             "they match.");
  }

  // Copy over the PCAP global file header
  PcapFile::FileHeader file_header = \
      PcapFile::GetStandardHeader(packets_a.GetLinkLayer());
  std::memcpy(data, &file_header, sizeof(PcapFile::FileHeader));
  data += sizeof(PcapFile::FileHeader);

  // Add the packet data to the file
  size_t count_a = 0;
  size_t count_b = 0;

  // First loop through packets until at least one of packets_a or packets_b
  // is finished.
  while (count_a < packets_a.Size() && count_b < packets_b.Size()) {
    // Skip through B until there is an unmatched (added) packet
    if (packets_b[count_b].match) {
      count_b++;
      continue;
    }
    // Output packets from A until the right slot for the unmatched 
    // packet from B.
    if (packets_a[count_a].header.time < packets_b[count_b].header.time) {
      CopyHeaderIncLen(data, packets_a[count_a].header);
      data += sizeof(PcapFile::PacketHeader);
      std::memcpy(data, packets_a[count_a].data.data(), 
                  packets_a[count_a].data.size());
      // Set last byte of packet to 0 if packet matches or 1
      // if it doesn't (i.e. it is not present in file B).
      data += packets_a[count_a].data.size();
      *data = packets_a[count_a].match ? 0 : 1;
      data++;
      count_a++;
    } else {
      CopyHeaderIncLen(data, packets_b[count_b].header);
      data += sizeof(PcapFile::PacketHeader);
      std::memcpy(data, packets_b[count_b].data.data(), 
              packets_b[count_b].data.size());
      data += packets_b[count_b].data.size();
      // Set last byte of packet to 2 to indicate
      // that packet was added.
      *data = 2;
      data++;
      count_b++;
    }
  }
  // Next loop through any remaining packets in A
  while (count_a < packets_a.Size()) {
    CopyHeaderIncLen(data, packets_a[count_a].header);
    data += sizeof(PcapFile::PacketHeader);
    std::memcpy(data, packets_a[count_a].data.data(), 
                packets_a[count_a].data.size());
    data += packets_a[count_a].data.size();
    *data = packets_a[count_a].match ? 0 : 1;
    data++;
    count_a++;
  }
  // Finally loop through any remaining packets in B
  while (count_b < packets_b.Size()) {
    CopyHeaderIncLen(data, packets_b[count_b].header);
    data += sizeof(PcapFile::PacketHeader);
    std::memcpy(data, packets_b[count_b].data.data(), 
            packets_b[count_b].data.size());
    data += packets_b[count_b].data.size();
    *data = 2;
    data++;
    count_b++;
  }
}

void PcapWriter::CopyHeaderIncLen(uint8_t* data, 
                                  PcapFile::PacketHeader header) {
  header.incl_len++;
  header.orig_len++;
  std::memcpy(data, &header, sizeof(PcapFile::PacketHeader));
}

void PcapWriter::WritePcapFull(const std::string& /*filename*/,
                               const Packets& /*packets_a*/,
                               const Packets& /*packets_b*/) {

}

PcapWriter::Mode PcapWriter::StringToMode(const std::string& mode) {
  if (mode == "basic") {
    return PcapWriter::Mode::Basic;
  } else if (mode == "full") {
    return PcapWriter::Mode::Full;
  } else if (mode == "match_a") {
    return PcapWriter::Mode::MatchA;
  } else if (mode == "match_b") {
    return PcapWriter::Mode::MatchB;
  } else if (mode == "added") {
    return PcapWriter::Mode::Added;
  } else if (mode == "removed") {
    return PcapWriter::Mode::Removed;
  } else {
    throw std::runtime_error("Invalid PCAP write mode: " + mode);
  }
  return PcapWriter::Mode::Basic;
}

