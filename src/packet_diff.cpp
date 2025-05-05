#include <stdexcept>
#include <algorithm>
#include <regex>
#include <iostream>

#include <packet_diff.h>


PacketDiff::PacketDiff(const std::string& search_mode,
                       const std::string& mask,
                       const std::string& range_a,
                       const std::string& range_b,
                       const std::pair<Timestamp, Timestamp>& time_range)
    : search_method_(ParseSearchMethod(search_mode)),
      mask_(MaskStringToVector(mask)),
      range_a_(RangeStringToPair(range_a)),
      range_b_(RangeStringToPair(range_b)),
      time_range_(time_range) {

  if (range_a_.second > 0 && range_b_.second > 0) {
    if (static_cast<size_t>(range_a_.second) <= range_a_.first) {
      throw std::runtime_error("Invalid Byte Range. With range [X:Y]"
                               " X must be less than Y: " + range_a);
    } else if (static_cast<size_t>(range_b_.second) <= range_b_.first) {
      throw std::runtime_error("Invalid Byte Range. With range [X:Y]"
                               " X must be less than Y: " + range_b);
    } else if ((range_a_.second - range_a_.first) != 
               (range_b_.second - range_b_.first)) {
      throw std::runtime_error("Specified byte ranges have different"
                               " lengths. No packets will never match.");
    }
  }

}

std::vector<bool> PacketDiff::MaskStringToVector(const std::string& mask_str) {

  auto char_test = [](char c) {return c != '0' && c != '1';};
  if (std::find_if(
      mask_str.begin(), mask_str.end(), char_test) != mask_str.end()) {
    throw std::runtime_error("Mask string may only contain '0' and '1' "
                             "characters");
  }

  std::vector<bool> mask;
    mask.reserve(mask_str.size());
    for (const auto& bit : mask_str) {
      mask.push_back(bit == '1');
    }
    return mask;
}

std::pair<size_t, int> PacketDiff::RangeStringToPair(
    const std::string& range_str) {

  std::pair<size_t, int> range;

  std::regex pattern(R"(\[(\d*):(-?\d*)\])");
  std::smatch matches;

  if (std::regex_match(range_str, matches, pattern)) {
    try {
      range.first = matches[1].str().empty() ? 0 : std::stoi(matches[1].str());
      range.second = matches[2].str().empty() ? 0 : std::stoi(matches[2].str());
    } catch (std::exception&) {
      throw std::runtime_error("Integer in " + range_str + " is out of range");
    }
  } else {
    throw std::runtime_error("Range format must be '[X:Y]', "
                             "'[X:]', '[:Y]', or '[:]'. "
                             "Only Y can be negative.");
  }

  return range;
}

PacketDiff::SearchMethod PacketDiff::ParseSearchMethod(
    const std::string &search_method) {

  if (search_method == "timestamp") {
    return PacketDiff::SearchMethod::Timestamp;
  } else if (search_method == "full") {
    return PacketDiff::SearchMethod::Full;
  } else if (search_method == "location") {
    return PacketDiff::SearchMethod::Location;
  } else {
    throw std::runtime_error("Invalid search method:" + search_method);
  }
}

void PacketDiff::FindMatching(Packets& packets_a, Packets& packets_b) {
  if (search_method_ == SearchMethod::Timestamp) {
    FindMatchingTimestampSearch(packets_a, packets_b);
  } else if (search_method_ == SearchMethod::Full) {
    FindMatchingFullSearch(packets_a, packets_b);
  } else { // search_method_ == SearchMethod::Location
    FindMatchingLocationSearch(packets_a, packets_b);
  }
}

void PacketDiff::FindMatchingTimestampSearch(Packets& packets_a,
                                             Packets& packets_b) {

  auto it_b_start = packets_b.begin();

  for (auto& packet_a : packets_a) {

    if (packet_a.match) continue;

    Timestamp window_start = packet_a.header.time - time_range_.first;
    Timestamp window_end = packet_a.header.time + time_range_.second;

    // Move it_b_start to the first element in B within the time window.
    // PCAPs are in time order, so we can start the search at the
    // packet at the start of the last window
    it_b_start = std::lower_bound(it_b_start, packets_b.end(), window_start,
        [](const Packet& b, const Timestamp& start) {
            return b.header.time < start;
        });

    // Check for matching entries within the time window
    for (auto it_b = it_b_start; it_b != packets_b.end() &&
         it_b->header.time <= window_end; ++it_b) {

      if (!it_b->match && ComparePacket(packet_a, *it_b)) {
        packet_a.match = true;
        packet_a.match_packet = &(*it_b);
        it_b->match = true;
        it_b->match_packet = &packet_a;
        break;
      }
    }
  }
}

void PacketDiff::FindMatchingFullSearch(Packets& packets_a,
                                        Packets& packets_b) {
  for (auto& packet_a : packets_a) {
    for (auto& packet_b : packets_b) {
      if (packet_b.match) continue;
      if (ComparePacket(packet_a, packet_b)) {
        packet_a.match = true;
        packet_a.match_packet = &packet_b;
        packet_b.match = true;
        packet_b.match_packet = &packet_a;
        break;
      }
    }
  }
}

void PacketDiff::FindMatchingLocationSearch(Packets& /*packets_a*/,
                                            Packets& /*packets_b*/) {
  throw std::runtime_error("Search method 'location' is currently unsupported");
}

bool PacketDiff::ComparePacket(const Packet& packet_a,
                               const Packet& packet_b) const {

  size_t index_a = range_a_.first;
  size_t index_b = range_b_.first;
  size_t end_a = packet_a.data.size();
  size_t end_b = packet_b.data.size();

  if (index_a >= packet_a.data.size()) return false;
  if (range_a_.second <= 0) {
    end_a += range_a_.second;
  } else {
    end_a = static_cast<size_t>(range_a_.second);
  }
  if (end_a > packet_a.data.size()) return false;

  if (index_b >= packet_b.data.size()) return false;
  if (range_b_.second <= 0) {
    end_b += range_b_.second;
  } else {
    end_b = static_cast<size_t>(range_b_.second);
  }
  if (end_b > packet_b.data.size()) return false;

  if ((end_a - index_a) != end_b - index_b) return false;

  // Mask is likely much smaller than the packet.
  // Mask is applied from the start offset of each packet.
  // After the mask finishes, all bytes are compared.
  // We know that length of packets is the same (taking into account
  // start / end offset).
  size_t index_mask =  0;
  while (index_mask < mask_.size() && index_a < end_a) {
    if (mask_[index_mask] == 1 &&
        (packet_a.data[index_a] != packet_b.data[index_b])) {
      return false;
    }
    index_a++;
    index_b++;
    index_mask++;
  }
  
  while (index_a < end_a) {
    if (packet_a.data[index_a] != packet_b.data[index_b]) {
      return false;
    }
    index_a++;
    index_b++;
  }

  return true;
}
