#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

#include <mapped_file.h>


MappedFile::MappedFile(const std::string& path, bool writable, size_t size) :
    writable_(writable) {

  if (writable) {
    fd_ = open(path.c_str(), O_RDWR | O_CREAT, 0664);
  } else {
    fd_ = open(path.c_str(), O_RDONLY);
  }

  if (fd_ == -1) {
    throw std::runtime_error("Failed to open file: " + path);
  }

  if (writable) {
    // Force file to be specified size
    if (ftruncate(fd_, size) == -1) {
      close(fd_);
      throw std::runtime_error("Failed to create file: " + path +
                               " with size: " + std::to_string(size));
    }
    size_ = size;
  } else {
    // Read the size of the file from disk
    struct stat sb;
    if (fstat(fd_, &sb) == -1) {
      close(fd_);
      throw std::runtime_error("Failed to get file size of file: " + path);
    }
    size_ = sb.st_size;
  }

  if (writable) {
    data_ = static_cast<uint8_t*>(
        mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
  } else {
    data_ = static_cast<uint8_t*>(
        mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0));
  }
  if (data_ == MAP_FAILED) {
    close(fd_);
    throw std::runtime_error("Failed to map file: " + path +
                             ". " + std::strerror(errno));
  }
}    

MappedFile::MappedFile(MappedFile&& other) noexcept 
    : fd_(other.fd_),
      data_(other.data_),
      size_(other.size_) {
  other.fd_ = -1;
  other.data_ = nullptr;
  other.size_ = 0;
  // No need to run Cleanup() as *this had not been previously constructed
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
  if (this != &other) {
    Cleanup();
    fd_ = other.fd_;
    data_ = other.data_;
    size_ = other.size_;
    other.fd_ = -1;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

MappedFile::~MappedFile() {
    Cleanup();
}

const uint8_t* MappedFile::Data() const { return data_; }

uint8_t* MappedFile::DataWritable() {
  if (!writable_) {
    throw std::runtime_error("Non-const access to read only file.");
  }
  return data_;
}

size_t MappedFile::Size() const { return size_; }

void MappedFile::Cleanup() {
  if (data_ != nullptr && data_ != MAP_FAILED) {
    munmap(data_, size_);
  }
  if (fd_ != -1) {
    close(fd_);
  }
}
