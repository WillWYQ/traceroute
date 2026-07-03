CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -pedantic -pthread

TARGET := traceroute
SRC    := traceroute.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
