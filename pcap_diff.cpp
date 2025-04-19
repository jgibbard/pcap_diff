// g++ -O3 --std=c++11 -Wpedantic -Wextra -Wall -Werror -Wfatal-errors packets.cpp pcap_diff.cpp packet_diff.cpp mapped_file.cpp pcap_reader.cpp pcap_writer.cpp timestamp.cpp pcap_file.cpp -I./include -o pcap_diff
#include <stdexcept>
#include <iostream>
#include <vector>
#include <sstream> 
#include <iomanip>

#include <args.h>
#include <pcap_reader.h>
#include <packets.h>
#include <packet_diff.h>
#include <pcap_writer.h>


std::string print_string_vector(const std::vector<std::string>& vec) {
  std::ostringstream oss;
  for (auto it = vec.begin(); it != vec.end(); ++it) {
    oss << *it;
    if (std::next(it) != vec.end()) {
      oss << ", ";
    }
  }
  return oss.str();
}

int main(int argc, char* argv[]) {

  /****************************************************************************/
  /*                         Command line arguments                           */
  /****************************************************************************/
  args::ArgumentParser parser("PCAP Diff Tool");
  args::Positional<std::string> filename_a(
      parser, "File A", "Filename for file A", {args::Options::Required});
  args::Positional<std::string> filename_b(
      parser, "File B", "Filename for file B", {args::Options::Required});  
  args::ValueFlag<uint64_t> max_packets(
      parser, "num packets", "Maximum mumber of packets",
      {"max-packets", 'n'}, 0);
  args::ValueFlag<std::string> byte_mask(
      parser, "mask", "Diff byte mask", {"byte-mask", 'm'}, "");
  args::ValueFlag<std::string> byte_range_a(
      parser, "range", "Diff byte range for packets in file A",
      {"range-a", 'a'}, "[:]");
  args::ValueFlag<std::string> byte_range_b(
      parser, "range", "Diff byte range for packets in file B",
      {"range-b", 'b'}, "[:]");
  args::Flag auto_timestamp_align(
      parser,"Auto time align", "Automatically align timestamps",
      {'A', "auto-time-align"});
  args::ValueFlag<double> time_offset_a(
      parser, "seconds", "Offset applied to file A timestamps",
      {"time-offset-a", 't'}, 0.0);
  args::ValueFlag<double> time_offset_b(
      parser, "seconds", "Offset applied to file B timestamps",
      {"time-offset-b", 'T'}, 0.0);
  args::ValueFlag<double> time_range_min(
      parser, "seconds", "Maximum negative time difference",
      {"neg-time-diff", 'd'}, 0.01);
  args::ValueFlag<double> time_range_max(
      parser, "seconds", "Maximum positive time difference",
      {"pos-time-diff", 'D'}, 0.01);
  args::ValueFlag<std::string> search_method(
      parser, "method", "Packet search method: ['timestamp'|'full'|'location']",
      {"search-method", 'm'}, "timestamp");
  args::ValueFlag<std::string> output_format(
      parser, "format", "Output format: ['basic'|'full'|'match_a'|'match_b'|"
                        "'added'|'removed']",{"output-format", 'f'}, "basic");
  args::ValueFlag<std::string> output_filename(
        parser, "filename", "Output filename", {"output", 'o'});
  args::Flag verbose(
      parser,"Verbose", "Print verbose output", {'v', "verbose"});
  args::HelpFlag help(
      parser, "help", "Display this help menu", {'h', "help"});

  try {
      parser.ParseCLI(argc, argv);
  }
  catch (const args::Error& e) {
    if (std::string(e.what()) != "help") {
      std::cerr << e.what() << "\n" << std::endl;
    }
    std::cerr << parser;
    return 2;
  }

  if (auto_timestamp_align && (
        args::get(time_offset_a) != 0.0 ||
        args::get(time_offset_b) != 0.0)) {
    std::cerr << "--time-offset-[a|b] and --auto-time-align "
                 "are muturally exclusive options \n" << std::endl;
    return 2;
  }

  std::vector<std::string> output_formats{
      "basic","full", "match_a", "match_b", "added", "removed"};
  if (std::find(output_formats.begin(),
                output_formats.end(),
                args::get(output_format)) == output_formats.end()) {
    
    std::cerr << "Output format must be one of the following options: ";
    std::cerr << print_string_vector(output_formats) << std::endl;
    return 2;
  }

  std::vector<std::string> search_methods{"timestamp", "full", "location"};
  if (std::find(search_methods.begin(), search_methods.end(),
                args::get(search_method)) == search_methods.end()) {
    std::cerr << "Search method must be one of the following options: ";
    std::cerr << print_string_vector(search_methods) << std::endl;
    return 2;
  }

  /****************************************************************************/
  /*                         Load packets from file                           */
  /****************************************************************************/

  Packets packets_a, packets_b;
  try {
    {
      if (verbose) std::cerr << "Reading File A: " << args::get(filename_a);
      PcapReader pcap(args::get(filename_a));
      packets_a.Load(
        pcap.GetPackets(args::get(max_packets)), pcap.GetLinkLayer()
      );
      if (verbose) std::cerr << " - Done" << std::endl;
    }
    {
      if (verbose) std::cerr << "Reading File B: " << args::get(filename_b);
      PcapReader pcap(args::get(filename_b));
      packets_b.Load(
        pcap.GetPackets(args::get(max_packets)), pcap.GetLinkLayer()
      );
      if (verbose) std::cerr << " - Done" << std::endl;
    }
  }
  catch (const std::runtime_error& error) {
    std::cerr << "\nERROR: " << error.what() << std::endl;
    return 2;
  }

  if (verbose) {
    std::cerr << "\nFile A - " << packets_a.GetMetadataString() << std::endl;
    std::cerr << "File B - " << packets_b.GetMetadataString() << std::endl;
  }

  if (args::get(output_format) == "basic") {
    if (packets_a.GetLinkLayer() != packets_b.GetLinkLayer()) {
      std::cerr << "PCAP Link layer of File A and File B differs. "
                   "The 'basic' output format requires that they match. "
                   "Select a different output mode." << std::endl;
      return 2;
    }
  }

  /****************************************************************************/
  /*                            Adjust Timestamps                             */
  /****************************************************************************/
  double offset_a = args::get(time_offset_a);
  double offset_b = args::get(time_offset_b);

  if (auto_timestamp_align) {
    std::cerr << "Auto timestamp alignment is currently unsupported";
    std::cerr << std::endl;
    return 2;
  }

  packets_a.OffsetTimestamps(offset_a);
  if (verbose && offset_a != 0.0) {
    std::cerr << "\nFile A - Applying time offset: " << offset_a << " seconds.";
    std::cerr << " New start time: " << packets_a.GetStartTimeString();
    std::cerr << std::endl;
  }

  packets_b.OffsetTimestamps(offset_b);
  if (verbose &&  offset_b != 0.0) {
    std::cerr << "\nFile B - Applying time offset: " << offset_b << " seconds.";
    std::cerr << " New start time: " << packets_b.GetStartTimeString();
    std::cerr << std::endl;
  }

  /****************************************************************************/
  /*                            Compare packets                               */
  /****************************************************************************/
  try {
    PacketDiff packet_diff(args::get(search_method),
                           args::get(byte_mask),
                           args::get(byte_range_a),
                           args::get(byte_range_b),{
                           args::get(time_range_min),
                           args::get(time_range_max)});
    packet_diff.FindMatching(packets_a, packets_b);
  } catch (const std::runtime_error& error) {
    std::cerr << "\nERROR: " << error.what() << std::endl;
    return 2;
  }

  auto no_match = [](const Packet& packet) {return !packet.match;};
  size_t num_rem = std::count_if(packets_a.begin(), packets_a.end(), no_match);
  size_t num_add = std::count_if(packets_b.begin(), packets_b.end(), no_match);
  if (verbose) {
    size_t num_match = packets_a.Size() - num_rem;
    std::cerr << "\nMatched: " << std::setw(9) << num_match;
    std::cerr << " [Packets in both A and B]\n";
    std::cerr << "Removed: " << std::setw(9) << num_rem;
    std::cerr << " [Packets in A only]" << std::endl;
    std::cerr << "Added:   " <<  std::setw(9) << num_add;
    std::cerr << " [Packets in B only]\n";
  }

  /****************************************************************************/
  /*                          Write output PCAP file                          */
  /****************************************************************************/
  if (output_filename) {
    try {
      if (verbose) std::cerr << "\nWriting file: "<< args::get(output_filename);
      PcapWriter::WritePcap(args::get(output_filename), packets_a, packets_b,
                            args::get(output_format));
      if (verbose) std::cerr << " - Done" << std::endl;
    } catch (const std::runtime_error& error) {
      std::cerr << "\nERROR: " << error.what() << std::endl;
      return 2;
    }
  }
  // Return 0 if PCAPs match, 1 if they differ
  return (num_rem == 0 && num_add == 0) ? 0 : 1;
}