# CMakeList.txt : 최상위 CMake 프로젝트 파일, 전역 구성을 수행하고
# 여기에 하위 프로젝트를 포함합니다.
#
cmake_minimum_required (VERSION 3.14)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 지원되는 경우 MSVC 컴파일러에 대해 핫 다시 로드 사용하도록 설정합니다.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()


#프로젝트 정보
project ("SysMonitor-Agent" LANGUAGES CXX C)

include(FetchContent)

FetchContent_Declare(
	spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog
	GIT_TAG v1.x
)

FetchContent_Declare(
	duckdb
	GIT_REPOSITORY https://github.com/duckdb/duckdb
	GIT_TAG v1.1.3
)

# DuckDB 빌드 옵션 설정
set(BUILD_UNITTESTS OFF CACHE BOOL "" FORCE)
set(BUILD_SHELL     OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
	grpc
	GIT_REPOSITORY https://github.com/grpc/grpc
	GIT_TAG v1.66.0
)

FetchContent_Declare(
	nlohmann_json
	GIT_REPOSITORY https://github.com/nlohmann/json
	GIT_TAG v3.11.3
)

# inih (agent.ini 파싱용) - CMakeLists가 없는 저장소라 소스만 받아 직접 컴파일한다 (src/CMakeLists.txt 참고).
FetchContent_Declare(
	inih
	GIT_REPOSITORY https://github.com/benhoyt/inih
	GIT_TAG r58
)

# gRPC 빌드 옵션 설정 (필요한 것만 빌드)
set(FETCHCONTENT_QUIET OFF)
set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(gRPC_BUILD_CSHARP_EXT OFF CACHE BOOL "" FORCE)
set(gRPC_SSL_PROVIDER "module" CACHE STRING "" FORCE)
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)
set(ABSL_ENABLE_INSTALL ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(spdlog duckdb grpc nlohmann_json)

FetchContent_GetProperties(inih)
if(NOT inih_POPULATED)
	FetchContent_Populate(inih)
endif()

# 하위 프로젝트를 포함합니다.
add_subdirectory ("src")
