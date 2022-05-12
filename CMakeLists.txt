cmake_minimum_required(VERSION 2.6)

project(ofilmopssl C)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

# only build examples if this is the main project
if(CMAKE_PROJECT_NAME STREQUAL "muduo")
  option(MUDUO_BUILD_EXAMPLES "Build Muduo examples" ON)
endif()

set(C_FLAGS
 -g     #调试信息
 # -DVALGRIND
 -DCHECK_PTHREAD_RETURN_VALUE     #-D开头编译定义变量
 -D_FILE_OFFSET_BITS=64           #-D开头编译定义变量
 -Wall              #对大部分警告都提示
 -Wextra            #一些额外的警告
# -Werror            #当出现警告时,警告变错误,停止编译
 -Wconversion       #可能改变值隐式装换时,警告 例如将double数据给了int数据类型
 -Wno-unused-parameter  #未使用的参数不给警告
 #-Wold-style-cast       #C风格的装换给出警告
 #-Woverloaded-virtual   #函数的声明,隐藏了基类的虚函数,给警告
 -Wpointer-arith        #对函数指针或者void *类型指针进行算数操作时给出警告
 -Wshadow               #当一个局部变量遮盖了另一个局部变量,或者全局变量时,给出警告
 -Wwrite-strings        #字符串常量类型是const char chptr[len],把这样的地址复制给no-const char*指针是产生警告
 -march=native          #指定cpu体系结构为本地平台 x84 armv4
 # -MMD
 -rdynamic
 )
if(CMAKE_BUILD_BITS EQUAL 32)
  list(APPEND C_FLAGS "-m32")
endif()
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  list(APPEND C_FLAGS "-Wno-null-dereference")
  list(APPEND C_FLAGS "-Wno-sign-conversion")
  list(APPEND C_FLAGS "-Wno-unused-local-typedef")
  list(APPEND C_FLAGS "-Wthread-safety")
  list(REMOVE_ITEM C_FLAGS "-rdynamic")
endif()
string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "-O0")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)


#find_package(ZLIB)

if(ZLIB_FOUND)
  message(STATUS "found zlib")
endif()


include_directories(${PROJECT_SOURCE_DIR})

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "C_FLAGS = " ${CMAKE_C_FLAGS} " " ${CMAKE_C_FLAGS_${BUILD_TYPE}})
add_subdirectory(OfiOpssl)


file(COPY  build.sh DESTINATION ${PROJECT_BINARY_DIR}/test)

