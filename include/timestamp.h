#pragma once
#include <cstdint>
#include <string>

struct Timestamp {
  Timestamp(uint32_t ts_sec, uint32_t ts_usec);
  Timestamp(double time);
  uint32_t ts_sec;
  uint32_t ts_usec;
  bool operator==(const Timestamp& other) const;
  bool operator!=(const Timestamp& other) const;
  bool operator<(const Timestamp& other) const;  
  bool operator<=(const Timestamp& other) const;
  bool operator>(const Timestamp& other) const;  
  bool operator>=(const Timestamp& other) const;
  Timestamp& operator+=(Timestamp rhs);
  Timestamp& operator-=(Timestamp rhs);
  Timestamp operator-(const Timestamp& other);
  Timestamp operator+(const Timestamp& other);
  std::string PrintTime() const;
};