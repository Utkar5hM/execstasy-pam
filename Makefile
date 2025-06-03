SRC_DIR := ./src
BUILD_DIR := ./build
OUTPUT_DIR := ./output
TARGET := $(OUTPUT_DIR)/pamshi.so
LIB_DIR := /lib64/security

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

CC := gcc
CFLAGS := -fPIC -I$(SRC_DIR)
LDFLAGS := -shared -lpam -lcurl

TEST_SERVICE ?= sshd
USER ?= $(shell whoami)

all: $(BUILD_DIR) $(OUTPUT_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) | $(OUTPUT_DIR)
	$(CC) $(LDFLAGS) -o $@ $^

install: $(TARGET)
	sudo cp $(TARGET) $(LIB_DIR)/pamshi.so

test: install
	sudo pamtester -v $(TEST_SERVICE) $(USER) authenticate

clean:
	rm -rf $(BUILD_DIR) $(OUTPUT_DIR)