#include <sstream>
#include <iomanip>

#include <packets.h>
#include <timestamp.h>


Packets::Packets() 
    : link_layer_(0) { }

void Packets::Load(std::vector<Packet> packets, uint32_t link_layer) {
    packets_ = std::move(packets);
    link_layer_ = link_layer;
}

Packet& Packets::operator[](size_t index) {
  return packets_[index];
}

const Packet& Packets::operator[](size_t index) const {
  return packets_[index];
}

std::string Packets::GetMetadataString() const {
  if (packets_.size() == 0) {
    throw std::runtime_error("Cannot print packet metadata. "
                             "No packets loaded");
  }
  std::ostringstream oss;  
  oss << "Num packets: " << std::setw(9) << packets_.size();
  oss << ". Link type: 0x" << std::hex << std::setfill('0');
  oss << std::setw(9) << link_layer_ << std::dec;
  oss << ". Start Time: " << packets_[0].header.time.PrintTime();
  return oss.str();
}

std::string Packets::GetStartTimeString() const {
  return packets_[0].header.time.PrintTime();
}

uint32_t Packets::GetLinkLayer() const {
  return link_layer_;
}

void Packets::OffsetTimestamps(double time_offset) {

  if (time_offset != 0.0) {
    if (time_offset > 0.0) {
      Timestamp offset(time_offset);
      for (auto& packet : packets_) {
        packet.header.time += offset;
      }
    } else {
      Timestamp offset(-time_offset);
      for (auto& packet : packets_) {
        packet.header.time -= offset;
      }
    }
  }

}

std::vector<Packet>::iterator Packets::begin() {
  return packets_.begin();
}

std::vector<Packet>::iterator Packets::end() {
  return packets_.end();
}

const std::vector<Packet>::const_iterator Packets::begin() const {
  return packets_.begin();
}

const std::vector<Packet>::const_iterator Packets::end() const {
  return packets_.end();
}

size_t Packets::Size() const {
  return packets_.size();
}