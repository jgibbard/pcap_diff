SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
INSTALL_DIR := /usr/local/bin

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(notdir $(SRCS)))
DEPS := $(OBJS:.o=.d)
TARGET := pcap_diff

CXX := g++
CXXFLAGS := -std=c++11 -Wpedantic -Wextra -Wall -Werror -Wfatal-errors
CXXFLAGS += -I$(INC_DIR)

DEBUG_FLAGS := -g -O0 -DDEBUG
RELEASE_FLAGS := -O3

ifeq ($(BUILD),debug)
	CXXFLAGS += $(DEBUG_FLAGS)
else
	CXXFLAGS += $(RELEASE_FLAGS)
endif

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(OBJS) $(TARGET).cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

debug:
	@$(MAKE) BUILD=debug

install: $(BUILD_DIR)/$(TARGET)
	install -d $(INSTALL_DIR)
	install -m 755 $(BUILD_DIR)/$(TARGET) $(INSTALL_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean debug install