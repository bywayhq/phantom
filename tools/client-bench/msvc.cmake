# cmake-rs 0.1.58 replaces MSVC configuration flags while discarding /O options.
# Keep this benchmark's native TLS code optimized and retain native symbols.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2 /Zi /DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/O2 /Zi /DNDEBUG" CACHE STRING "" FORCE)
