#include <stdexcept>
#include <ctime>
#include <cmath>
#include <string>
#include <iomanip>
#include <sstream>
#include <limits>

#include <timestamp.h>

Timestamp::Timestamp(uint32_t ts_sec, uint32_t ts_usec)
    : ts_sec(ts_sec), ts_usec(ts_usec) {
  if (ts_usec >= 1000000) {
    throw std::runtime_error("Timestamp microseconds cannot be >= 1000000");
  }
}

Timestamp::Timestamp(double time) {
  if (time < 0.0) {
    throw std::runtime_error("Timestamp cannot be negative");
  }

  double integer_seconds = 0.0;
  double fractional_seconds = std::modf(time, &integer_seconds);

  if (integer_seconds >= std::numeric_limits<uint32_t>::max()) {
    throw std::runtime_error("Timestamp value too large");
  }

  // Floor to avoid ever rounding up to 1000000
  double micro_seconds = std::floor(fractional_seconds * 1000000);

  ts_sec = static_cast<uint32_t>(integer_seconds);
  ts_usec = static_cast<uint32_t>(micro_seconds);

}

bool Timestamp::operator==(const Timestamp &other) const
{
  return ts_sec == other.ts_sec && ts_usec == other.ts_usec;
}

bool Timestamp::operator!=(const Timestamp& other) const {
  return !(*this == other);
}

bool Timestamp::operator<(const Timestamp& other) const {
  return (ts_sec < other.ts_sec) ||
         (ts_sec == other.ts_sec && ts_usec < other.ts_usec);
}

bool Timestamp::operator<=(const Timestamp& other) const {
  return *this < other || *this == other;
}

bool Timestamp::operator>(const Timestamp& other) const {
  return other < *this;
}

bool Timestamp::operator>=(const Timestamp& other) const {
  return !(*this < other);
}

Timestamp& Timestamp::operator+=(Timestamp rhs) {

  ts_sec += rhs.ts_sec;
  ts_usec += rhs.ts_usec;

  if (ts_usec >= 1000000) {
    ts_sec++;
    ts_usec -= 1000000;
  }

  return *this;
}

Timestamp& Timestamp::operator-=(Timestamp rhs) {
  // Invalid when rhs is greater than this timestamp
  // We could check for this, but this would be wasteful 
  // in this application
  ts_sec -= rhs.ts_sec;
  ts_usec -= rhs.ts_usec;

  // Detect wrap of usec
  if (ts_usec >= 1000000) {
    ts_sec--;
    ts_usec += 1000000;
  }

  return *this;
}

Timestamp Timestamp::operator-(const Timestamp& other) {
  uint32_t ts_sec_sum = this->ts_sec - other.ts_sec;
  uint32_t ts_usec_sum = this->ts_usec - other.ts_usec;

  // Detect wrap of usec
  if (ts_usec_sum >= 1000000) {
    ts_sec_sum--;
    ts_usec_sum += 1000000;
  }

  return Timestamp{ts_sec_sum, ts_usec_sum};
}

Timestamp Timestamp::operator+(const Timestamp& other) {
  uint32_t ts_sec_sum = this->ts_sec + other.ts_sec;
  uint32_t ts_usec_sum = this->ts_usec + other.ts_usec;

  if (ts_usec_sum >= 1000000) {
    ts_sec_sum++;
    ts_usec_sum -= 1000000;
  }

  return Timestamp{ts_sec_sum, ts_usec_sum};
}

std::string Timestamp::PrintTime() const {
  std::time_t t = static_cast<std::time_t>(ts_sec);
  std::tm* tm_ptr = std::localtime(&t);
  std::ostringstream oss;
  oss << std::put_time(tm_ptr, "%Y-%m-%d %H:%M:%S");
  oss << '.' << std::setfill('0') << std::setw(3) << (ts_usec / 1000);
  return oss.str();
}