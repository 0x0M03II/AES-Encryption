cmake_minimum_required(VERSION 3.27)
project(aes_assignment)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(aes_assignment main.cpp
        aes.h
        aes.cpp)
