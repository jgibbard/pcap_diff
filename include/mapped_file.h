#pragma once
#include <cstdint>
#include <string>

/**
 * @brief Class for memory mapping a file
 * 
 */
class MappedFile {
  public:
    MappedFile(const std::string& path, bool writable = false, size_t size = 0);
    // Class manages a resource that needs a custom destructor
    ~MappedFile();
    // Custom destructor therefore "rule of 5" applies
    // Disable copy constructor and copy assignment
    // Not required for application and sharing the 
    // resource would require a lot of additional code
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    // Move assignment and move constructor allowed 
    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    const uint8_t* Data() const;
    uint8_t* DataWritable();
    size_t Size() const;
  private:
    void Cleanup();
    int fd_ = -1;
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
    bool writable_;
};