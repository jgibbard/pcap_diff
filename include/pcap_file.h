#pragma once
#include <cstdint>
#include <cstddef>

#include <timestamp.h>

namespace PcapFile {

  struct FileHeader {
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snap_length;
    uint32_t link_type;
  };
  
  struct PacketHeader {
    struct Timestamp time;
    uint32_t incl_len;
    uint32_t orig_len;
  };
  
  struct FileHeader GetStandardHeader(uint32_t link_layer);

}




