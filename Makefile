CC = clang

# build dir
build:
	mkdir -p build/xdp

# Top-level directories.
BUILD_DIR = build
SRC_DIR = src
XDP_DIR = $(SRC_DIR)/xdp

# Additional build directories.
BUILD_XDP_DIR = $(BUILD_DIR)/xdp

# XDP directories.
XDP_SRC =  $(SRC_DIR)/main.c
XDP_OBJ = xdp.o

# Includes.
INCS = -I $(SRC_DIR) -I /usr/include -I /usr/local/include

# Flags.
FLAGS = -O2 -g
FLAGS_LOADER = -lconfig -lelf -lz

all: build xdp

# XDP program.
xdp: build
	$(CC) $(INCS) $(FLAGS) -target bpf -c $(XDP_SRC) -o $(BUILD_XDP_DIR)/$(XDP_OBJ)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean xdp build