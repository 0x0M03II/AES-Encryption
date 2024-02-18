#!/bin/bash

# Script to compile C++ files

# Define the source files
SOURCE_FILES="main.cpp aes.cpp"

# Define the output executable name
OUTPUT="aesprogram"

# Compile the program
g++ -o $OUTPUT $SOURCE_FILES

# Check if the compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful. Executable created: $OUTPUT"
else
    echo "Compilation failed."
fi
