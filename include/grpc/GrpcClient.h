#pragma once

#include <string>
#include <memory>
#include <optional>

#include "models/SnapShotData.h"

class GapBuffer;

// 연결 / 전송 결과. 값은 "호출부가 다음에 무엇을 해야 하는가" 기준으로 나눈다.
// gRPC 타입(grpc::Status)을 헤더에 노출하지 않기 위해 자체 enum을 쓴다 (pimpl 유지).
enum class ClientResult {
    Ok,
    Disconnected,     // 연결 실패 / 스트림 끊김 / 서버 무응답 → 백오프 재연결 + 로컬 버퍼 (GrpcClient가 스스로 처리한다)
    Unauthenticated,  // UNAUTHENTICATED / PERMISSION_DENIED → 재시도해도 소용없음
    Fatal,            // 그 외 예상 밖 상태 (예: proto 불일치 FAILED_PRECONDITION, 다른 PC가 같은 agent_id 사용 ALREADY_EXISTS) → 재시도해도 소용없음
};

// 서버로 가는 전송 전체를 맡는다: 연결(Hello + 재개 지점 조회) / 실시간 전송 / 끊김 감지 / 백오프 재연결 / 갭 전송.
// 네트워크 작업은 모두 내부 스레드에서 하므로 메인 루프는 전송 때문에 멈추지 않는다 —
// 서버가 응답하지 않는 연결에서는 Write()가 수십 초 이상 막힐 수 있다 (실측).
//
// 스레드:
//   - 실시간 스레드: 연결하고, 메인 루프가 넘긴 틱을 실시간 스트림에 쓰고, 끊기면 지수 백오프(±25% 지터)로 다시 연결한다.
//   - 확인 스레드: 연결 중 10초마다 GetResumePoint(기한 10초)로 서버가 실시간 채널에서 마지막으로 읽은 시각을 묻는다.
//       ① 그 시각의 틱을 보낸 순서에서 찾아, 그보다 먼저 쓴 틱을 메모리 보관분에서 지운다 — PC 시계가 뒤로 갈 수 있어
//          시각의 크기는 비교하지 않는다
//       ② 답이 없으면 연결을 끊는다 — 상대가 데이터를 받지 않는 채 TCP 연결만 살아 있으면 gRPC keepalive ping이
//          나가지도 못해 끊김이 영영 감지되지 않는다 (실측)
//   - 갭 스레드: 연결될 때마다 로컬 버퍼에 쌓인 스냅샷을 배치 스트림으로 보낸다. 묶음마다 스트림을 열고 닫아,
//     서버가 OK로 끝낸 묶음만 버퍼에서 지운다.
//
// Write()가 성공해도 서버가 받았다는 보장은 없다 (전송 대기열에 들어갔을 뿐). 그래서 실시간으로 쓴 틱은 서버가 받았다고
// 확인될 때까지 메모리에 둔다 (최대 600틱 — 넘치면 오래된 것부터 로컬 버퍼로). 끊기면 확인되지 않은 틱과 아직 못 쓴 틱을
// 로컬 버퍼로 옮기고, 다시 연결되면 그 연결의 재개 지점으로 버퍼를 정리한 뒤(서버가 읽은 틱보다 먼저 쓴 것만 지운다)
// 나머지를 모두 보낸다.
//
// 로컬 버퍼(GapBuffer)는 메인 루프 스레드에서만 다룬다: 송신 스레드는 버퍼 작업을 큐에 넣고, 메인 루프가
// runBufferTasks()에서 실행해 결과를 돌려준다.
class GrpcClient {
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

public:
    // instanceId는 모든 RPC의 metadata "instance_id"로 실린다 (gRPC metadata 규칙상 출력 가능한 ASCII여야 함).
    // 같은 값이 로컬 버퍼의 "수집한 장비"로도 기록된다.
    GrpcClient(std::string serverUrl, std::string agentId, std::string apiKey, std::string instanceId);
    // 스레드를 멈추고 기다린다. 막혀 있는 RPC는 취소한다.
    ~GrpcClient();

    GrpcClient(const GrpcClient&) = delete;
    GrpcClient& operator=(const GrpcClient&) = delete;
    GrpcClient(GrpcClient&&) = delete;            // 내부 스레드가 Impl을 가리키므로 옮기지 않는다
    GrpcClient& operator=(GrpcClient&&) = delete;

    // 스레드를 띄우고 첫 연결 시도의 결과를 기다려 돌려준다 (최대 약 10초).
    // Unauthenticated / Fatal이면 스레드는 이미 멈췄다 — 호출부는 종료한다.
    // Disconnected면 스레드가 백오프로 계속 다시 시도한다 — 그 사이 틱은 로컬 버퍼로 간다.
    ClientResult start();

    // 한 틱의 sys / proc / target 스냅샷을 넘긴다 (메인 루프 스레드, 막히지 않는다).
    // 연결돼 있으면 실시간 스레드가 보내고, 아니면 로컬 버퍼 작업으로 넘어간다.
    // proc이 nullopt이면(이번 틱에 프로세스 목록을 만들지 못함) proc 메시지는 만들지 않는다 — 빈 목록으로 보내지 않는다.
    void submit(const SnapshotSysData& sys, const std::optional<SnapshotProcData>& proc, const SnapshotTargetData& target);

    // 송신 스레드가 요청한 로컬 버퍼 작업을 실행한다. 메인 루프 스레드에서만 부를 것.
    void runBufferTasks(GapBuffer& buffer);

    // 재시도해도 소용없는 결과(Unauthenticated / Fatal)로 전송이 멈췄으면 그 결과. 원인은 이미 로그로 남겼다.
    std::optional<ClientResult> stopped() const;
};
