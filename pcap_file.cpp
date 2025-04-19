#include <pcap_file.h>

struct PcapFile::FileHeader PcapFile::GetStandardHeader(uint32_t link_layer) {

  FileHeader file_header{
    0xA1B2C3D4, // magic_number
    4,          // major_version
    2,          // minor_version
    0,          // thiszone
    0,          // sigfigs
    65535,      // snap_length
    link_layer
  };

  return file_header;
}