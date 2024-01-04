cmake_minimum_required(VERSION 3.10)

# Set the project name
project(Walrus CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(SEAL 4.1 REQUIRED)

# Add tests executable
add_executable(apiTests examples/tests.cpp src/ctxt.cpp src/evaluator.cpp)
target_include_directories(apiTests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(apiTests SEAL::seal)
target_include_directories(apiTests PRIVATE ${SEAL_INCLUDE_DIRS})

# Add temp executable for noise analysis
add_executable(noiseTests examples/noise_tests.cpp src/ctxt.cpp src/evaluator.cpp)
target_include_directories(noiseTests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(noiseTests SEAL::seal)
target_include_directories(noiseTests PRIVATE ${SEAL_INCLUDE_DIRS})

# Add neural network executable 
add_executable(neuralNetwork examples/neural_network.cpp src/ctxt.cpp src/evaluator.cpp src/parameterizer.cpp)
target_include_directories(neuralNetwork PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(neuralNetwork SEAL::seal)
target_include_directories(neuralNetwork PRIVATE ${SEAL_INCLUDE_DIRS})