#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

#include "grpc/GrpcClient.h"
#include "grpc/SnapshotConverter.h"
#include "datastore/GapBuffer.h"
#include <grpcpp/grpcpp.h>
#include "sysmonitor.grpc.pb.h"

using AgentDataWriter = grpc::ClientWriter<sysmonitor::AgentData>;
using namespace std::chrono_literals;

namespace {
    constexpr auto CONNECT_TIMEOUT = 5s;            // 채널이 READY가 될 때까지
    constexpr auto CONNECT_RPC_DEADLINE = 5s;       // 연결 절차의 Hello / GetResumePoint
    constexpr auto CONFIRM_INTERVAL = 10s;          // 연결 중 GetResumePoint 주기
    constexpr auto CONFIRM_DEADLINE = 10s;          // 이 안에 답이 없으면 연결을 끊는다
    constexpr size_t MAX_HELD_TICKS = 600;          // 메모리에 두는 틱의 상한 (확인 대기 / 전송 대기 각각) — 넘치면 오래된 것부터 로컬 버퍼로
    constexpr size_t GAP_CHUNK_ROWS = 300;          // 갭 전송 묶음 하나의 스냅샷 수 (= 배치 스트림 하나)
    constexpr int BACKOFF_MAX_SECONDS = 60;

    // 스냅샷 timestamp 단위 — epoch 마이크로초.
    int64_t epochMicros(std::chrono::system_clock::time_point tp) {
        return std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();
    }

    // 모든 RPC(Hello / GetResumePoint / StreamRealtime / StreamBatch)에 같은 신원 metadata를 싣는다 — 서버는 RPC마다 다시 확인한다.
    void addIdentity(grpc::ClientContext& ctx, const std::string& agentId, const std::string& apiKey, const std::string& instanceId) {
        ctx.AddMetadata("agent_id", agentId);
        ctx.AddMetadata("api_key", apiKey);
        ctx.AddMetadata("instance_id", instanceId);
    }

    // gRPC 상태 코드를 "호출부가 다음에 할 일" 기준의 ClientResult로 바꾼다. 모든 RPC 결과가 이 함수를 거친다.
    ClientResult toClientResult(const grpc::Status& status) {
        switch (status.error_code()) {
        case grpc::StatusCode::OK:
            return ClientResult::Ok;
        case grpc::StatusCode::UNAUTHENTICATED:
        case grpc::StatusCode::PERMISSION_DENIED:
            return ClientResult::Unauthenticated;
        case grpc::StatusCode::UNAVAILABLE:
        case grpc::StatusCode::DEADLINE_EXCEEDED:
        case grpc::StatusCode::CANCELLED:
        case grpc::StatusCode::ABORTED:
            return ClientResult::Disconnected;
        default:
            // FAILED_PRECONDITION(Hello의 protocol_version 불일치), ALREADY_EXISTS(다른 PC가 같은 agent_id로 접속 중),
            // UNIMPLEMENTED(서버에 RPC 없음), INVALID_ARGUMENT(서버가 메시지를 거부) 등 — 재연결해도 해결되지 않는 상태.
            return ClientResult::Fatal;
        }
    }

    // 로그용 상태 코드 이름. 서버가 표준 밖의 숫자를 보낼 수도 있으므로 모르는 값은 숫자 그대로 쓴다.
    std::string statusCodeName(grpc::StatusCode code) {
        switch (code) {
        case grpc::StatusCode::OK:                  return "OK";
        case grpc::StatusCode::CANCELLED:           return "CANCELLED";
        case grpc::StatusCode::UNKNOWN:             return "UNKNOWN";
        case grpc::StatusCode::INVALID_ARGUMENT:    return "INVALID_ARGUMENT";
        case grpc::StatusCode::DEADLINE_EXCEEDED:   return "DEADLINE_EXCEEDED";
        case grpc::StatusCode::NOT_FOUND:           return "NOT_FOUND";
        case grpc::StatusCode::ALREADY_EXISTS:      return "ALREADY_EXISTS";
        case grpc::StatusCode::PERMISSION_DENIED:   return "PERMISSION_DENIED";
        case grpc::StatusCode::RESOURCE_EXHAUSTED:  return "RESOURCE_EXHAUSTED";
        case grpc::StatusCode::FAILED_PRECONDITION: return "FAILED_PRECONDITION";
        case grpc::StatusCode::ABORTED:             return "ABORTED";
        case grpc::StatusCode::OUT_OF_RANGE:        return "OUT_OF_RANGE";
        case grpc::StatusCode::UNIMPLEMENTED:       return "UNIMPLEMENTED";
        case grpc::StatusCode::INTERNAL:            return "INTERNAL";
        case grpc::StatusCode::UNAVAILABLE:         return "UNAVAILABLE";
        case grpc::StatusCode::DATA_LOSS:           return "DATA_LOSS";
        case grpc::StatusCode::UNAUTHENTICATED:     return "UNAUTHENTICATED";
        default:                                    return std::to_string(static_cast<int>(code));
        }
    }

    // 끊김 감지용 keepalive. 스트림의 Write()는 전송 대기열에 넣기만 하면 성공하므로, 서버가 FIN/RST 없이 사라지면
    // (정전, 랜선, 패킷을 버리는 중간 장비) keepalive 없이는 끊김을 알 수 없다 — 실측에서 240초 동안 몰랐다.
    // 30초마다 ping을 보내 10초 안에 응답이 없으면 연결을 끊고, 그 뒤의 Write()가 실패해 Disconnected로 드러난다.
    // 상대가 데이터를 받지 않는 채 TCP 연결만 살아 있으면 ping 자체가 나가지 못해 이것으로는 감지되지 않는다 —
    // 그 경우는 확인 스레드의 GetResumePoint 기한 초과가 잡는다.
    // - 간격은 서버의 ping 허용 간격(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS = 20초) 이상이어야 한다.
    //   더 짧으면 서버가 too_many_pings로 연결을 끊는다 — 두 값은 계약이므로 한쪽을 바꾸면 다른 쪽도 확인할 것.
    // - ping 응답 대기(PING_TIMEOUT)는 keepalive를 켜면 기본 1분이라 KEEPALIVE_TIMEOUT만 줄여서는 감지가 늦다.
    //   공개 헤더에 없는 인자라 키 문자열을 직접 쓴다 — gRPC를 올리면 키가 그대로인지 다시 확인할 것.
    // - MAX_PINGS_WITHOUT_DATA는 0(제한 없음): 기본값 2는 데이터 프레임을 보내지 못하는 동안 ping을 2번까지만 허용하는데,
    //   끊김을 감지해야 하는 때가 바로 상대가 흐름 제어 창을 열어 주지 않아 데이터가 나가지 못하는 때다.
    grpc::ChannelArguments makeChannelArgs() {
        grpc::ChannelArguments args;
		args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 30 * 1000);     //30초마다 ping
		args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 10 * 1000);  //10초 안에 응답 없으면 연결 끊기
        args.SetInt("grpc.http2.ping_timeout_ms", 10 * 1000);   //기본 1분 -> 10초 (공개헤더에 없는키)
		args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);  //데이터가 막혀도 ping을 무제한 허용 (기본 2회)
        // 기본(전역 서브채널 풀)에서는 같은 주소로 새 채널을 만들어도, 다른 스레드가 옛 채널을 쥐고 있는 동안 옛 TCP 연결을 재사용한다.
        // 그 연결이 열린 채 막혀 있으면 ping도 나가지 못해 끊기지 않으므로 재연결의 Hello가 매번 기한을 넘긴다.
        // 채널마다 자기 연결을 갖게 해 재연결이 옛 채널을 쥔 스레드(확인 중인 GetResumePoint 등)를 기다리지 않게 한다.
        args.SetInt(GRPC_ARG_USE_LOCAL_SUBCHANNEL_POOL, 1);
        return args;
    }

    std::string describe(const std::optional<int64_t>& timestampUs) {
        return timestampUs ? std::to_string(*timestampUs) : std::string("none");
    }

    // 한 틱의 메시지들 (sys / proc / target, 모두 같은 timestamp)
    struct Tick {
        int64_t timestampUs = 0;
        std::vector<sysmonitor::AgentData> messages;
    };

    // 스코프를 벗어날 때 한 번 실행한다.
    template <typename F>
    class ScopeExit {
        F fn_;
    public:
        explicit ScopeExit(F fn) : fn_(std::move(fn)) {}
        ~ScopeExit() { fn_(); }
        ScopeExit(const ScopeExit&) = delete;
        ScopeExit& operator=(const ScopeExit&) = delete;
    };
} // namespace

struct GrpcClient::Impl {
    const std::string serverUrl;
    const std::string agentId;
    const std::string apiKey;
    const std::string instanceId;

    // 연결 하나 — 재연결마다 새로 만든다. 확인/갭 스레드는 shared_ptr로 잡고 쓰므로 실시간 스레드가 놓아도 안전하다.
    struct Connection {
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<sysmonitor::AgentService::Stub> stub;
    };

    // ---- 아래는 mtx로 보호 ----
    mutable std::mutex mtx;
    std::condition_variable cv;               // 전송 대기열 / 연결 상태 / 종료 변화를 알린다
    bool stopping = false;
    std::optional<ClientResult> stopReason;
    std::shared_ptr<Connection> conn;         // 연결돼 있을 때만 있다
    uint64_t generation = 0;                  // 연결에 성공할 때마다 1 증가 — 갭 스레드가 "새 연결"을 알아보는 데 쓴다
    std::deque<Tick> sendQueue;               // 넘겨받았지만 아직 쓰지 않은 틱
    std::deque<Tick> unconfirmed;             // 실시간 스트림에 썼지만 서버가 받았다고 확인되지 않은 틱
    grpc::ClientContext* realtimeCtx = nullptr;   // 막힌 Write()를 다른 스레드에서 취소하기 위한 포인터 (쓰는 스레드가 소유)
    grpc::ClientContext* batchCtx = nullptr;

    // ---- 로컬 버퍼 작업 큐 (메인 루프가 실행) ----
    std::mutex taskMtx;
    bool tasksClosed = false;
    std::deque<std::function<void(GapBuffer&)>> tasks;

    std::promise<ClientResult> firstResult;
    bool firstReported = false;               // 실시간 스레드만 쓴다

    std::thread realtimeThread;
    std::thread confirmThread;
    std::thread gapThread;

    Impl(std::string url, std::string id, std::string key, std::string instance)
        : serverUrl(std::move(url)), agentId(std::move(id)), apiKey(std::move(key)), instanceId(std::move(instance)) {}

    // ---------------- 로컬 버퍼 작업 ----------------

    // 틱을 버퍼 행으로 바꾼다 (메시지 1개 = 행 1개).
    void appendRows(const Tick& tick, bool sentRealtime, std::vector<BufferedSnapshot>& rows) const {
        for (const auto& message : tick.messages) {
            BufferedSnapshot row;
            row.timestampUs = tick.timestampUs;
            row.instanceId = instanceId;
            row.protocolVersion = static_cast<uint32_t>(sysmonitor::PROTOCOL_VERSION_CURRENT);
            row.sentRealtime = sentRealtime;
            message.SerializeToString(&row.payload);
            rows.push_back(std::move(row));
        }
    }

    // 버퍼에 넣는다 (결과를 기다리지 않는다).
    void postAppend(std::vector<BufferedSnapshot> rows) {
        if (rows.empty()) {
            return;
        }
        std::lock_guard<std::mutex> lock(taskMtx);
        if (tasksClosed) {
            return;
        }
        tasks.push_back([rows = std::move(rows)](GapBuffer& buffer) { buffer.append(rows); });
    }

    // 이 연결의 R로 버퍼를 정리하는 작업을 넣는다 (결과를 기다리지 않는다). 연결을 공개하는 mtx 블록 안에서 부른다 —
    // 작업 큐는 넣은 순서대로 실행되므로 "앞 연결의 버퍼 이동 → 이 연결의 정리 → 이 연결의 버퍼 이동"이 큐의 순서로 지켜지고,
    // 연결이 곧바로 끊겨도 정리가 빠지지 않는다. 갭 스레드의 버퍼 읽기도 이 작업 뒤에 들어간다.
    void postReconcileLocked(std::optional<int64_t> resumePoint) {
        std::lock_guard<std::mutex> lock(taskMtx);
        if (tasksClosed) {
            return;
        }
        tasks.push_back([resumePoint](GapBuffer& buffer) {
            const GapBuffer::ReconcileResult r = buffer.reconcile(resumePoint, static_cast<uint32_t>(sysmonitor::PROTOCOL_VERSION_CURRENT));
            if (r.versionDropped > 0) {
                spdlog::warn("[GrpcClient] dropped {} buffered snapshot(s) made by another protocol version — they cannot be sent", r.versionDropped);
            }
            if (r.confirmedDropped > 0) {
                spdlog::info("[GrpcClient] dropped {} buffered snapshot(s) already received by the server ({} left to send)", r.confirmedDropped, r.remaining);
            }
        });
    }

    // 메인 루프에서 fn(buffer)를 실행하고 결과를 기다린다. 종료 중이면 std::future_error를 던진다 (작업이 버려짐).
    template <typename F>
    auto callOnMain(F fn) -> decltype(fn(std::declval<GapBuffer&>())) {
        using R = decltype(fn(std::declval<GapBuffer&>()));
        auto task = std::make_shared<std::packaged_task<R(GapBuffer&)>>(std::move(fn));
        std::future<R> result = task->get_future();
        {
            std::lock_guard<std::mutex> lock(taskMtx);
            if (!tasksClosed) {
                tasks.push_back([task](GapBuffer& buffer) { (*task)(buffer); });
            }
        }
        task.reset();   // 큐에 넣지 못했다면 여기서 packaged_task가 사라져 get()이 broken_promise를 던진다
        return result.get();
    }

    // 확인되지 않은 틱과 쓰지 못한 틱을 로컬 버퍼로 옮긴다. mtx를 잡은 상태에서 부른다.
    void spillHeldTicksLocked() {
        std::vector<BufferedSnapshot> rows;
        for (const auto& tick : unconfirmed) {
            appendRows(tick, /*sentRealtime=*/true, rows);
        }
        for (const auto& tick : sendQueue) {
            appendRows(tick, /*sentRealtime=*/false, rows);
        }
        unconfirmed.clear();
        sendQueue.clear();
        postAppend(std::move(rows));
    }

    // ---------------- 종료 ----------------

    // 재시도해도 소용없는 결과로 전송을 멈춘다. 메인 루프가 stopped()로 알아보고 종료한다.
    void stopWith(ClientResult result) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (!stopReason) {
                stopReason = result;
            }
            stopping = true;
            cancelStreamsLocked();
        }
        cv.notify_all();
    }

    void cancelStreamsLocked() {
        if (realtimeCtx) realtimeCtx->TryCancel();      // 실시간 통화 강제 종료
        if (batchCtx) batchCtx->TryCancel();            // 공백 채우기 통화 강제 종료
    }

    void reportFirst(ClientResult result) {
        if (!firstReported) {
            firstReported = true;
            firstResult.set_value(result);
        }
    }

    // ---------------- 실시간 스레드 ----------------

    // 채널 생성 → READY 대기 → Hello(인증 + 프로토콜 버전) → GetResumePoint → 실시간 스트림 열기.
    ClientResult connectOnce(std::shared_ptr<Connection>& out, std::optional<int64_t>& resumePoint, grpc::ClientContext& streamCtx, sysmonitor::Ack& streamAck, std::unique_ptr<AgentDataWriter>& stream) {
        auto c = std::make_shared<Connection>();
        c->channel = grpc::CreateCustomChannel(serverUrl, grpc::InsecureChannelCredentials(), makeChannelArgs());

        // 채널은 lazy하게 연결된다. WaitForConnected()가 연결 시도를 시작하고 READY가 될 때까지 기다린다 —
        // 이게 없으면 서버가 없어도 아래 스트림 열기가 성공한 것처럼 보인다.
        if (!c->channel->WaitForConnected(std::chrono::system_clock::now() + CONNECT_TIMEOUT)) {
            spdlog::warn("[GrpcClient] could not reach {} within {}s", serverUrl, std::chrono::seconds(CONNECT_TIMEOUT).count());
            return ClientResult::Disconnected;
        }
        c->stub = sysmonitor::AgentService::NewStub(c->channel);

        // 스트림을 열기 전에 Hello로 인증을 먼저 확인한다. 스트림은 인증이 거부돼도 첫 Write()가
        // 실패할 때까지 원인이 드러나지 않지만, unary RPC는 거부 사유를 즉시 Status로 돌려준다.
        // (서버는 스트림에서도 다시 인증하므로 이건 보안 장치가 아니라 빠르고 명확한 실패를 위한 것.)
        grpc::ClientContext helloCtx;
        addIdentity(helloCtx, agentId, apiKey, instanceId);
        helloCtx.set_deadline(std::chrono::system_clock::now() + CONNECT_RPC_DEADLINE);
        sysmonitor::HelloRequest helloReq;
        helloReq.set_protocol_version(sysmonitor::PROTOCOL_VERSION_CURRENT);   // 서버와 proto가 어긋나면 FAILED_PRECONDITION → Fatal
        sysmonitor::Ack helloAck;
        grpc::Status helloStatus = c->stub->Hello(&helloCtx, helloReq, &helloAck);
        if (!helloStatus.ok()) {
            spdlog::error("[GrpcClient] hello rejected by {}: code={} message=\"{}\"", serverUrl, statusCodeName(helloStatus.error_code()), helloStatus.error_message());
            return toClientResult(helloStatus);
        }
        spdlog::info("[GrpcClient] server says: {}", helloAck.message());

        // 실시간 스트림을 열기 전에 묻는다 — 연 뒤에는 새 틱이 서버의 "마지막 수신 시각"을 앞으로 밀어,
        // 끊기기 전에 확인되지 않은 틱이 받은 것으로 잘못 정리된다.
        grpc::ClientContext resumeCtx;
        addIdentity(resumeCtx, agentId, apiKey, instanceId);
        resumeCtx.set_deadline(std::chrono::system_clock::now() + CONNECT_RPC_DEADLINE);
        sysmonitor::ResumePoint resume;
        grpc::Status resumeStatus = c->stub->GetResumePoint(&resumeCtx, sysmonitor::ResumePointRequest(), &resume);
        if (!resumeStatus.ok()) {
            spdlog::error("[GrpcClient] GetResumePoint failed on {}: code={} message=\"{}\"", serverUrl, statusCodeName(resumeStatus.error_code()), resumeStatus.error_message());
            return toClientResult(resumeStatus);
        }
        resumePoint = resume.has_last_realtime_timestamp_us() ? std::optional<int64_t>(resume.last_realtime_timestamp_us()) : std::nullopt;

        addIdentity(streamCtx, agentId, apiKey, instanceId);
        stream = c->stub->StreamRealtime(&streamCtx, &streamAck);
        if (!stream) {
            // WaitForConnected()가 이미 연결을 확인했으므로 null은 "서버 연결 실패"가 아니라 예상치 못한 내부 상태 이상이다.
            spdlog::error("[GrpcClient] unexpected null stream after successful connect to {}", serverUrl);
            return ClientResult::Fatal;
        }
        out = std::move(c);
        return ClientResult::Ok;
    }

    // 전송 대기열의 틱을 실시간 스트림에 쓴다. 스트림이 끝나면(끊김 / 거부 / 종료) 결과를 돌려준다.
    ClientResult streamRealtime(AgentDataWriter& stream) {
        while (true) {
            Tick tick;
            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return stopping || !sendQueue.empty(); });
                if (stopping) {
                    break;
                }
                tick = std::move(sendQueue.front());
                sendQueue.pop_front();
            }

            for (const auto& message : tick.messages) {
                if (stream.Write(message)) {
                    continue;
                }
                // Write()가 실패하면 Finish()로 서버가 보낸 최종 상태(예: UNAUTHENTICATED)를 회수한다.
                grpc::Status status = stream.Finish();
                spdlog::error("[GrpcClient] realtime stream closed: code={} message=\"{}\"", statusCodeName(status.error_code()), status.error_message());
                {
                    // 다 쓰지 못한 틱은 "보내지 않은 것"으로 되돌린다 — 일부가 서버에 갔다면 다시 보내 중복이 되지만, 잃지는 않는다.
                    std::lock_guard<std::mutex> lock(mtx);
                    sendQueue.push_front(std::move(tick));
                }
                // Write()가 실패했다면 상태가 OK로 오더라도 스트림은 이미 끝났다 — 재연결이 필요한 상태로 본다.
                ClientResult result = toClientResult(status);
                return result == ClientResult::Ok ? ClientResult::Disconnected : result;
            }

            std::vector<BufferedSnapshot> overflow;
            {
                std::lock_guard<std::mutex> lock(mtx);
                unconfirmed.push_back(std::move(tick));
                while (unconfirmed.size() > MAX_HELD_TICKS) {
                    appendRows(unconfirmed.front(), /*sentRealtime=*/true, overflow);
                    unconfirmed.pop_front();
                }
            }
            postAppend(std::move(overflow));
        }

        stream.WritesDone();
        stream.Finish();
        return ClientResult::Ok;
    }

    std::chrono::milliseconds backoffDelay(int failures, std::mt19937& rng) {
        // 1 → 2 → 4 → … → 60초. 서버가 재시작하면 모든 Agent가 거의 같은 순간에 끊김을 감지하므로,
        // 각 값에 ±25%를 섞어 재연결과 갭 전송이 한꺼번에 몰리지 않게 한다.
        const int seconds = std::min(BACKOFF_MAX_SECONDS, 1 << std::min(failures, 6));
        std::uniform_real_distribution<double> jitter(0.75, 1.25);
        return std::chrono::milliseconds(static_cast<int64_t>(seconds * 1000 * jitter(rng)));
    }

    void realtimeLoop() {
        std::mt19937 rng(std::random_device{}());
        int failures = 0;
        while (true) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (stopping) {
                    return;
                }
            }

            ClientResult result;
            {
                grpc::ClientContext streamCtx;   // stream보다 먼저 선언 — stream이 먼저 소멸해야 한다
                sysmonitor::Ack streamAck;
                std::unique_ptr<AgentDataWriter> stream;
                std::shared_ptr<Connection> c;
                std::optional<int64_t> resumePoint;
                result = connectOnce(c, resumePoint, streamCtx, streamAck, stream);
                reportFirst(result);

                if (result == ClientResult::Ok) {
                    failures = 0;
                    {
                        std::lock_guard<std::mutex> lock(mtx);
                        conn = c;
                        ++generation;
                        realtimeCtx = &streamCtx;
                        postReconcileLocked(resumePoint);   // 끊길 때의 버퍼 이동(아래 spillHeldTicksLocked)의 짝
                    }
                    cv.notify_all();
                    spdlog::info("[GrpcClient] connected to {} as {} (server's last realtime timestamp: {})", serverUrl, agentId, describe(resumePoint));

                    result = streamRealtime(*stream);

                    {
                        // 통신 종료 - 이 시점부터 submit()은 틱을 로컬 버퍼로 보낸다. 확인되지 않은 틱과 쓰지 못한 틱도 함께 옮긴다.
                        std::lock_guard<std::mutex> lock(mtx);
                        realtimeCtx = nullptr;
                        conn.reset();
                        if (batchCtx) batchCtx->TryCancel();
                        spillHeldTicksLocked();     // 미전송 및 미확인 틱을 디스크로
                    }
                    cv.notify_all();
                    if (result == ClientResult::Ok) {   // Disconnected, Unauthenticated, Fatal 일 시에 아래 switch문으로
                        return;   // 정상 통신 종료
                    }
                }
            }

            switch (result) {
            case ClientResult::Ok:
                return;     // 정상 종료
            case ClientResult::Disconnected:
                break;      // 재연결 - 아래 #449로
            case ClientResult::Unauthenticated:
            case ClientResult::Fatal:
                stopWith(result);
                return;     // 재연결의 의미 상실로 인한 비정상 종료
            }

            // 쉬었다가 재연결
            const auto delay = backoffDelay(failures++, rng);
            spdlog::warn("[GrpcClient] disconnected from {} — buffering snapshots locally, reconnecting in {:.1f}s", serverUrl, delay.count() / 1000.0);
            std::unique_lock<std::mutex> lock(mtx);
            if (cv.wait_for(lock, delay, [&] { return stopping; })) {
                return;     // 쉬는 도중 종료 신호시에 종료
            }
        }
    }

    // ---------------- 확인 스레드 ----------------

    void confirmLoop() {
        while (true) {
            std::shared_ptr<Connection> c;
            uint64_t gen = 0;
            {
                std::unique_lock<std::mutex> lock(mtx);
                if (cv.wait_for(lock, CONFIRM_INTERVAL, [&] { return stopping; })) {
                    return;
                }
                c = conn;               // 현재 연결
				gen = generation;       // 몇 번째 연결인지
            }
            if (!c) {
                continue;
            }

            grpc::ClientContext ctx;
            addIdentity(ctx, agentId, apiKey, instanceId);
            ctx.set_deadline(std::chrono::system_clock::now() + CONFIRM_DEADLINE);
            sysmonitor::ResumePoint resume;
            grpc::Status status = c->stub->GetResumePoint(&ctx, sysmonitor::ResumePointRequest(), &resume);

            std::lock_guard<std::mutex> lock(mtx);
            if (generation != gen || conn != c) {
                continue;   // 그 사이 연결이 바뀌었다
            }
            if (status.ok()) {
                if (resume.has_last_realtime_timestamp_us()) {
                    // 서버가 마지막으로 읽은 틱을 보낸 순서에서 찾아 그 앞만 지운다 — 시각의 크기로 비교하면 PC 시계가 뒤로 간 뒤의
                    // 틱이 받지 못했는데도 지워진다. 못 찾으면(그 틱이 이미 버퍼로 넘어갔거나 옛 연결의 것) 아무것도 지우지 않는다.
                    // 같은 timestamp의 틱은 일부만 받았을 수 있으므로 남긴다.
                    const int64_t last = resume.last_realtime_timestamp_us();
                    const auto readUpTo = std::find_if(unconfirmed.begin(), unconfirmed.end(), [last](const Tick& t) { return t.timestampUs == last; });
                    if (readUpTo != unconfirmed.end()) {
                        unconfirmed.erase(unconfirmed.begin(), readUpTo);
                    }
                }
                continue;
            }
            // 답이 없으면(기한 초과 등) 이 연결로는 더 보낼 수 없다고 보고 끊는다 — 막힌 Write()가 실패로 풀리고
            // 실시간 스레드가 재연결한다. 거부(인증 등)였다면 재연결의 Hello가 원인과 함께 다시 드러낸다.
            spdlog::warn("[GrpcClient] server did not confirm within {}s (code={} message=\"{}\") — dropping the connection", std::chrono::seconds(CONFIRM_DEADLINE).count(), statusCodeName(status.error_code()), status.error_message());
            cancelStreamsLocked();
        }
    }

    // ---------------- 갭 스레드 ----------------

    // 버퍼 행 묶음 하나를 배치 스트림 하나로 보낸다. 서버가 OK로 끝내야 Ok — 그때만 받은 것으로 본다.
    ClientResult sendChunk(Connection& c, uint64_t gen, const std::vector<BufferedSnapshot>& rows) {
        grpc::ClientContext ctx;
        addIdentity(ctx, agentId, apiKey, instanceId);
        {
            // 연결 확인과 batchCtx 공개를 같은 락 구간에서 한다 — 끊김 처리는 공개된 batchCtx만 취소할 수 있으므로,
            // 따로 확인하면 그 사이에 끊긴 연결로 기한 없는 스트림을 열어 아무도 취소하지 못한다.
            std::lock_guard<std::mutex> lock(mtx);
            if (stopping || generation != gen || !conn) {
                return ClientResult::Disconnected;
            }
            batchCtx = &ctx;
        }
        ScopeExit clearCtx([&] {
            std::lock_guard<std::mutex> lock(mtx);
            batchCtx = nullptr;
        });

        sysmonitor::Ack ack;
        std::unique_ptr<AgentDataWriter> stream = c.stub->StreamBatch(&ctx, &ack);
        if (!stream) {
            return ClientResult::Disconnected;
        }
        bool written = true;
        for (const auto& row : rows) {
            sysmonitor::AgentData data;
            if (!data.ParseFromString(row.payload)) {
                spdlog::error("[GrpcClient] buffered snapshot id={} is corrupt — skipped", row.id);
                continue;
            }
            data.set_collected_instance_id(row.instanceId); // 이 PC의 instanceId가 아닌 행에 기록된 instanceId를 전송
            if (!stream->Write(data)) {
                written = false;
                break;
            }
        }
        if (written) {
            stream->WritesDone();
        }
        grpc::Status status = stream->Finish();
        if (status.ok() && written) {
            return ClientResult::Ok;
        }
        spdlog::warn("[GrpcClient] gap stream closed: code={} message=\"{}\"", statusCodeName(status.error_code()), status.error_message());
        ClientResult result = toClientResult(status);
        return result == ClientResult::Ok ? ClientResult::Disconnected : result;
    }

    // 정리는 실시간 스레드가 연결을 공개할 때 이미 큐에 넣었다 — 아래의 버퍼 읽기는 모두 그 뒤에 실행된다.
    void sendGap(const std::shared_ptr<Connection>& c, uint64_t gen) {
        const size_t remaining = callOnMain([](GapBuffer& buffer) { return buffer.count(); });
        if (remaining == 0) {
            return;
        }
        spdlog::info("[GrpcClient] gap fill: {} buffered snapshot(s) to send", remaining);

        int64_t lastId = 0;
        size_t sent = 0;
        while (true) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (stopping || generation != gen || !conn) {
                    spdlog::info("[GrpcClient] gap fill interrupted after {} snapshot(s) — the rest is sent on the next connection", sent);
                    return;
                }
            }
            const std::vector<BufferedSnapshot> rows = callOnMain([lastId](GapBuffer& buffer) { return buffer.readAfter(lastId, GAP_CHUNK_ROWS); });
            if (rows.empty()) {
                break;
            }
            const ClientResult result = sendChunk(*c, gen, rows);
            switch (result) {
            case ClientResult::Ok:
                break;
            case ClientResult::Disconnected:
                spdlog::info("[GrpcClient] gap fill interrupted after {} snapshot(s) — the rest is sent on the next connection", sent);
                return;
            case ClientResult::Unauthenticated:
            case ClientResult::Fatal:
                // 실시간 전송은 계속한다. 남은 갭은 버퍼에 두고 다음 연결 때 다시 시도한다.
                spdlog::error("[GrpcClient] server rejected gap data — {} snapshot(s) stay in the local buffer until the next connection", remaining - sent);
                return;
            }
            lastId = rows.back().id;
            callOnMain([lastId](GapBuffer& buffer) { buffer.removeUpTo(lastId); return 0; });
            sent += rows.size();
        }
        spdlog::info("[GrpcClient] gap fill done: {} snapshot(s) sent", sent);
    }

    void gapLoop() {
        uint64_t handled = 0;
        while (true) {
            std::shared_ptr<Connection> c;
            uint64_t gen = 0;
            {
                // 연결을 건너뛰어도 된다 — 정리는 연결마다 실시간 스레드가 넣었고, 남은 행은 다음 연결에서 보낸다.
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] { return stopping || (conn && generation != handled); });
                if (stopping) {
                    return;
                }
                c = conn;
                gen = generation;
                handled = generation;
            }
            try {
                sendGap(c, gen);
            }
            catch (const std::future_error&) {
                return;   // 종료 중 — 버퍼 작업 큐가 닫혔다
            }
        }
    }
};

GrpcClient::GrpcClient(std::string serverUrl, std::string agentId, std::string apiKey, std::string instanceId)
    : impl_(std::make_unique<Impl>(std::move(serverUrl), std::move(agentId), std::move(apiKey), std::move(instanceId))) {}

GrpcClient::~GrpcClient() {
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->stopping = true;
        impl_->cancelStreamsLocked();
    }
    impl_->cv.notify_all();
    {
        std::lock_guard<std::mutex> lock(impl_->taskMtx);
        impl_->tasksClosed = true;
        impl_->tasks.clear();   // 결과를 기다리던 갭 스레드는 broken_promise로 깨어난다
    }
    for (std::thread* t : { &impl_->realtimeThread, &impl_->confirmThread, &impl_->gapThread }) {
        if (t->joinable()) {
            t->join();
        }
    }
}

ClientResult GrpcClient::start() {
    std::future<ClientResult> first = impl_->firstResult.get_future();
    impl_->realtimeThread = std::thread([this] { impl_->realtimeLoop(); });
    impl_->confirmThread = std::thread([this] { impl_->confirmLoop(); });
    impl_->gapThread = std::thread([this] { impl_->gapLoop(); });
    return first.get();
}

void GrpcClient::submit(const SnapshotSysData& sys, const std::optional<SnapshotProcData>& proc, const SnapshotTargetData& target) {
    // 메인 루프에서 1초마다 호출
    // collector 내용 sendQueue 안에 담기
    // 스냅샷 1건 = 메시지 1개. 한 틱의 메시지는 모두 같은 timestamp를 싣는다 (메인 루프가 틱마다 하나로 정한다).
    Tick tick;
    tick.timestampUs = epochMicros(sys.timestamp);
    tick.messages.push_back(SnapshotConverter::toAgentData(impl_->agentId, sys));
    if (proc) {
        tick.messages.push_back(SnapshotConverter::toAgentData(impl_->agentId, *proc));
    }
    tick.messages.push_back(SnapshotConverter::toAgentData(impl_->agentId, target));

    std::vector<BufferedSnapshot> rows;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->conn && !impl_->stopping) {
            impl_->sendQueue.push_back(std::move(tick));
            // 서버가 받지 않는 동안 대기열이 끝없이 자라지 않게 한다 — 확인 스레드가 곧 연결을 끊지만, 그 전까지의 상한.
            // 넘친 것은 로컬 버퍼(디스크)로
            while (impl_->sendQueue.size() > MAX_HELD_TICKS) {
                impl_->appendRows(impl_->sendQueue.front(), /*sentRealtime=*/false, rows);
                impl_->sendQueue.pop_front();
            }
        } else {
            // 끊겨 있다면 로컬 버퍼(디스크)로
            impl_->appendRows(tick, /*sentRealtime=*/false, rows);
        }
    }
    impl_->cv.notify_all();
    impl_->postAppend(std::move(rows));
}

void GrpcClient::runBufferTasks(GapBuffer& buffer) {
    std::deque<std::function<void(GapBuffer&)>> pending;
    {
        std::lock_guard<std::mutex> lock(impl_->taskMtx);
        pending.swap(impl_->tasks);
    }
    for (auto& task : pending) {
        task(buffer);
    }
}

std::optional<ClientResult> GrpcClient::stopped() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->stopReason;
}
