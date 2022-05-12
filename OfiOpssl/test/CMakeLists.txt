set(echo_SRCS
  test.c
  )

set(TEST_COPY_FILE
CMakeList_i.txt
test.c
test.h
test.txt
)
file(COPY  ${TEST_COPY_FILE} DESTINATION ${PROJECT_BINARY_DIR}/test)

add_executable(testMain ${echo_SRCS})
target_link_libraries(testMain ofopssl)





