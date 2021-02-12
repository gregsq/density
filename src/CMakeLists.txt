include(cppflags)

add_executable(densityapp
  densityapp.cpp
  epoller.cpp)

include_directories(
  ../inc
)

target_link_libraries(densityapp
)


# The rule to install densityapp binary
install (TARGETS densityapp
	RUNTIME
	DESTINATION bin)
  
