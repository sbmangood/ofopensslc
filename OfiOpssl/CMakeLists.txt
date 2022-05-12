set(echo_SRCS
  common_st.c
  ofHash.c
  ofAsAlgoTools.c
  ofAES_Tools.c
  )


set(HEAD_FILES_ 
  common_st.h
  ofAES_Tools.h
  ofAsAlgoTools.h
  ofHash.h
)
file(COPY  ${HEAD_FILES_} DESTINATION ${PROJECT_BINARY_DIR}/include/OfiOpssl)

add_library(ofopssl SHARED ${echo_SRCS})
target_link_libraries(ofopssl  ssl crypto)



add_subdirectory(test)




