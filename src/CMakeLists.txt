# CMakeList.txt: SysMonitor-Agent에 대한 CMake 프로젝트, 여기에 소스를 포함하고
# 프로젝트 특정 논리를 정의합니다.
#
# 수집기/저장소 로직은 SysMonitorAgentCore 정적 라이브러리로 분리해 구성합니다.
# (테스트·gRPC·ApiServer 등 여러 실행 파일에서 공통으로 재사용하기 위함)
# main / gRPC 진입점(SysMonitor.cpp, ApiServer.cpp)이 준비되면 이 파일에
# add_executable(SysMonitorAgent ...) 타겟을 추가하고 SysMonitorAgentCore를 링크합니다.

add_library (SysMonitorAgentCore STATIC
	"collectors/SystemCollector.cpp" "collectors/CpuCollector.cpp" "collectors/MemCollector.cpp" "collectors/NetCollector.cpp" "collectors/DiskCollector.cpp"
	"collectors/ProcessCollector.cpp" "collectors/ETWNetwork.cpp" "collectors/TargetCollector.cpp"
	"datastore/DataStore.cpp" "datastore/SummaryStore.cpp"
	"analysis/SessionReport.cpp")
target_include_directories(SysMonitorAgentCore PUBLIC "../include")

target_compile_definitions(SysMonitorAgentCore PRIVATE
    _WINSOCKAPI_        # winsock.h 자동 include 차단
    WIN32_LEAN_AND_MEAN # windows.h 경량화
)


target_link_libraries(SysMonitorAgentCore PUBLIC
                                            duckdb
                                            spdlog::spdlog
                                            nlohmann_json::nlohmann_json
                                            pdh
                                            iphlpapi    # GetAdaptersAddresses
                                            tdh         # TdhEnumerateProviders
                                            ws2_32      # inet_addr, inet_ntop
                                            secur32)

if (CMAKE_VERSION VERSION_GREATER 3.14)
  set_property(TARGET SysMonitorAgentCore PROPERTY CXX_STANDARD 20)
endif()

# --- Phase 1: gRPC 뼈대 -----------------------------------------------
# proto/sysmonitor.proto로부터 *.pb.cc/*.grpc.pb.cc를 빌드 시점에 생성한다.

set(PROTO_DIR "${CMAKE_SOURCE_DIR}/proto")
set(PROTO_FILE "${PROTO_DIR}/sysmonitor.proto")
set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

set(PROTO_SRCS "${PROTO_GEN_DIR}/sysmonitor.pb.cc")
set(PROTO_HDRS "${PROTO_GEN_DIR}/sysmonitor.pb.h")
set(GRPC_SRCS "${PROTO_GEN_DIR}/sysmonitor.grpc.pb.cc")
set(GRPC_HDRS "${PROTO_GEN_DIR}/sysmonitor.grpc.pb.h")

add_custom_command(
	OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
	COMMAND $<TARGET_FILE:protoc>
	ARGS --grpc_out=${PROTO_GEN_DIR}
	     --cpp_out=${PROTO_GEN_DIR}
	     --plugin=protoc-gen-grpc=$<TARGET_FILE:grpc_cpp_plugin>
	     -I ${PROTO_DIR}
	     ${PROTO_FILE}
	DEPENDS ${PROTO_FILE} protoc grpc_cpp_plugin
)

add_library(SysMonitorProto STATIC ${PROTO_SRCS} ${GRPC_SRCS})
target_include_directories(SysMonitorProto PUBLIC ${PROTO_GEN_DIR})
target_link_libraries(SysMonitorProto PUBLIC grpc++ libprotobuf)

# --- Phase 2: agent.ini 파싱 (inih) ------------------------------------
# inih 저장소에는 CMakeLists.txt가 없어 ini.c / cpp/INIReader.cpp를 직접 컴파일한다.
add_library(inih STATIC "${inih_SOURCE_DIR}/ini.c" "${inih_SOURCE_DIR}/cpp/INIReader.cpp")
target_include_directories(inih PUBLIC "${inih_SOURCE_DIR}" "${inih_SOURCE_DIR}/cpp")

# main / gRPC 클라이언트 진입점
add_executable(SysMonitorAgent "grpc/GrpcClient.cpp" "SysMonitorAgent.cpp" "AgentConfig.cpp")
target_link_libraries(SysMonitorAgent PRIVATE SysMonitorAgentCore SysMonitorProto inih)

if(MSVC)
    # 소스 인코딩을 UTF-8로 강제 (BOM 유무와 무관하게 안전)
    target_compile_options(SysMonitorAgentCore PRIVATE /utf-8)
    target_compile_options(SysMonitorProto PRIVATE /utf-8)
    target_compile_options(SysMonitorAgent PRIVATE /utf-8)
    target_compile_options(inih PRIVATE /utf-8)
endif()
