#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace duckdb {
    class DuckDB;
    class Connection;
}

// 버퍼의 한 행 = 스냅샷 1건.
struct BufferedSnapshot {
    int64_t id = 0;                 // 버퍼가 매기는 순번 — 넣은 순서대로 보낸다 (append()에 넘길 때는 무시된다)
    int64_t timestampUs = 0;        // 스냅샷의 틱 시각 (epoch 마이크로초)
    std::string instanceId;         // 수집한 장비 — 버퍼는 설치 폴더와 함께 다른 PC로 복사될 수 있다
    uint32_t protocolVersion = 0;   // payload를 만든 proto 버전 — 지금 버전과 다르면 보낼 수 없다
    bool sentRealtime = false;      // 실시간 채널로 이미 쓴 적이 있다 (서버가 받았는지는 모른다)
    std::string payload;            // 직렬화된 전송 메시지
};

// 서버와 연결이 끊긴 동안의 스냅샷을 보관하는 로컬 DuckDB 버퍼.
// 스냅샷은 전송 메시지를 직렬화한 바이트 그대로 저장한다: 꺼내서 다시 보내기만 하므로 지표의 구조를 알 필요가 없고,
// "수집하지 못한 값"(메시지의 optional 필드가 없음)이 0으로 바뀌지 않고 그대로 돌아간다.
// 대신 로컬에서 지표를 SQL로 조회할 수는 없다 — 조회는 서버의 몫이다.
// 메인 루프 스레드에서만 쓴다. 송신 스레드는 GrpcClient의 작업 큐를 거친다.
// 파일을 열지 못하면 오류를 한 번 남기고 아무것도 저장하지 않는 상태로 동작한다 (실시간 전송은 계속된다).
class GapBuffer {
public:
    GapBuffer(const std::string& path, int retentionHours);
    ~GapBuffer();

    GapBuffer(const GapBuffer&) = delete;
    GapBuffer& operator=(const GapBuffer&) = delete;

    void append(const std::vector<BufferedSnapshot>& rows);

    struct ReconcileResult {
        size_t confirmedDropped = 0;   // 서버가 이미 받은 것으로 확인돼 지운 행
        size_t versionDropped = 0;     // 다른 proto 버전으로 만들어져 보낼 수 없어 지운 행
        size_t remaining = 0;          // 보낼 행
    };
    // 연결마다 정확히 1번, 그 연결의 버퍼 이동보다 먼저 부른다 (GrpcClient가 연결을 공개할 때 작업 큐에 넣는다).
    // serverLastUs = 서버가 실시간 채널에서 마지막으로 읽은 timestamp (없으면 서버가 아는 기록이 없다).
    // 실시간으로 이미 쓴 행 중 그 timestamp의 첫 행보다 먼저 쓴 것은 서버가 받았으므로 지운다 — 시각의 크기는 비교하지 않는다
    // (PC 시계가 뒤로 가면 받지 못한 행도 더 작은 시각을 갖는다). 같은 timestamp는 틱의 일부만 받았을 수 있어 남긴다.
    // 남은 행은 모두 "보내야 할 행"으로 바꾼다: 실시간으로 쓴 행은 직전 연결 하나의 것이어야, 그 연결의 R로 판정한 결과가 맞다.
    ReconcileResult reconcile(std::optional<int64_t> serverLastUs, uint32_t currentProtocolVersion);

    // id가 afterId보다 큰 행을 순번대로 최대 limit개.
    std::vector<BufferedSnapshot> readAfter(int64_t afterId, size_t limit);
    // 서버가 받은 것으로 확인된 행(id ≤ lastId)을 지운다.
    void removeUpTo(int64_t lastId);
    // 보관 시간이 지난 행을 지운다. 지운 행 수를 돌려준다.
    size_t dropExpired(int64_t nowUs);
    size_t count();

private:
    std::unique_ptr<duckdb::DuckDB> db_;
    std::unique_ptr<duckdb::Connection> con_;
    int64_t retentionUs_;
    int64_t nextId_ = 1;
    bool dropWarned_ = false;   // 열지 못한 버퍼로 들어온 행을 버린다는 경고를 이미 남겼는가
};
