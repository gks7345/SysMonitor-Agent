#pragma once

#include <string>
#include <memory>

// connect()/send*()의 결과. 값은 "호출부가 다음에 무엇을 해야 하는가" 기준으로 나눈다.
// gRPC 타입(grpc::Status)을 헤더에 노출하지 않기 위해 자체 enum을 쓴다 (pimpl 유지).
enum class ClientResult {
    Ok,
    Disconnected,     // 연결 실패 / 스트림 끊김 / 미연결 상태에서 send 호출 → Phase 4: 백오프 재연결 + 로컬 버퍼
    Unauthenticated,  // UNAUTHENTICATED / PERMISSION_DENIED → 재시도해도 소용없음
    Fatal,            // 그 외 예상 밖 상태 (예: proto 불일치로 인한 UNIMPLEMENTED) → 재시도해도 소용없음
};

// Phase 1: gRPC 뼈대 — 더미 데이터를 실시간/배치 채널로 각각 전송한다.
// Phase 2: 연결 시 api_key를 gRPC metadata에 실어 보낸다. Phase 3에서 실제 수집 데이터로 교체 예정.
class GrpcClient {
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::string serverUrl_;
    std::string agentId_;
    std::string apiKey_;
    std::string instanceId_;   // 설치(PC) 단위 고유값 — 같은 agent_id를 쓰는 다른 PC를 서버가 구분하는 데 쓴다

public:
    // instanceId는 모든 RPC의 metadata "instance_id"로 실린다 (gRPC metadata 규칙상 출력 가능한 ASCII여야 함).
    GrpcClient(std::string serverUrl, std::string agentId, std::string apiKey, std::string instanceId);
    ~GrpcClient();

    GrpcClient(const GrpcClient&) = delete;             // ① 복사 생성자 금지
    GrpcClient& operator=(const GrpcClient&) = delete;  // ② 복사 대입 금지
    GrpcClient(GrpcClient&&) noexcept;                  // ③ 이동 생성자
    // ④ 이동 대입은 당장 쓸 곳이 없어 제거 (`= default`로 두면 ~GrpcClient()의 WritesDone()/Finish() 정상 종료를 우회하는 결함이 있었음).
    // 재연결 등으로 실제로 필요해지면, closeStreams()를 먼저 호출하도록 직접 작성해서 되살릴 것.
    GrpcClient& operator=(GrpcClient&&) = delete;

    // 서버에 연결한다 (Phase 1: insecure channel, Phase 2: metadata에 agent_id/api_key 포함).
    // 스트림을 열기 전에 Hello RPC로 인증을 먼저 확인하므로, 잘못된 api_key는 여기서 Unauthenticated로 드러난다.
    // 이미 연결된 상태에서 다시 호출해도 안전하다 — 기존 스트림을 먼저 정상 종료(closeStreams())한 뒤 새로 연다.
    ClientResult connect();

    // sys / proc / target 더미 스냅샷을 실시간 채널로 한 건씩(메시지 3개) 전송한다. Phase 3에서 실제 수집 데이터로 교체.
    // 스트림이 끊기면 서버가 보낸 최종 상태를 로그로 남기고 스트림을 버린다 — 이후 호출은 재연결 전까지 Disconnected.
    ClientResult sendRealtimeDummy();

    // 배치 채널 연결 확인용 더미 sys 스냅샷 1건을 전송한다. Phase 4-4에서 갭 전송으로 교체.
    // 실패 처리는 sendRealtimeDummy()와 같다.
    ClientResult sendBatchDummy();

private:
    // 열려 있는 스트림이 있으면 WritesDone()+Finish()로 정상 종료한다.
    // 소멸자와 connect()(재연결 시 기존 스트림 정리) 양쪽에서 공유하는 로직.
    void closeStreams();
};
