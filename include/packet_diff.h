#pragma once
#include <utility>
#include <functional>


#include <packets.h>

class PacketDiff {
  public:

    PacketDiff(const std::string& search_mode,
               const std::string& mask,
               const std::string& range_a,
               const std::string& range_b,
               const std::pair<Timestamp, Timestamp>& time_range);
    void FindMatching(Packets& packets_a, Packets& packets_b);
 
  private:
    enum class SearchMethod {Timestamp, Full, Location};
    static std::vector<bool> MaskStringToVector(const std::string& mask_str);
    static std::pair<size_t, int> RangeStringToPair(
          const std::string& range_str);

    SearchMethod search_method_;
    std::vector<bool> mask_;
    std::pair<size_t,int> range_a_;
    std::pair<size_t,int> range_b_;
    std::pair<Timestamp, Timestamp> time_range_;
    SearchMethod ParseSearchMethod(const std::string& search_method);
    void FindMatchingTimestampSearch(Packets& packets_a, Packets& packets_b);
    void FindMatchingFullSearch(Packets& packets_a, Packets& packets_b);
    void FindMatchingLocationSearch(Packets& packets_a, Packets& packets_b);
    bool ComparePacket(const Packet& packet_a, const Packet& packet_b) const;

  };
