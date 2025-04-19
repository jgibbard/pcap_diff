#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <packet.h>


class Packets {
  public:
    Packets();
    void Load(std::vector<Packet>, uint32_t link_layer);
    size_t Size() const;
    Packet& operator[](size_t index);
    const Packet& operator[](size_t index) const;
    std::string GetMetadataString() const;
    std::string GetStartTimeString() const;
    uint32_t GetLinkLayer() const;
    void OffsetTimestamps(double time_offset);
    std::vector<Packet>::iterator begin();    
    std::vector<Packet>::iterator end();
    const std::vector<Packet>::const_iterator begin() const;    
    const std::vector<Packet>::const_iterator end() const;
  private:
    std::vector<Packet> packets_;
    uint32_t link_layer_;
};