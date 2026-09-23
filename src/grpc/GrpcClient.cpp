#include <chrono>
#include <spdlog/spdlog.h>

#include "grpc/GrpcClient.h"
#include <grpcpp/grpcpp.h>
#include "sysmonitor.grpc.pb.h"

using AgentDataWriter = grpc::ClientWriter<sysmonitor::AgentData>;

namespace {
    // 스냅샷 timestamp 단위 — DataStore::toTimestamp()와 같은 epoch 마이크로초.
    int64_t nowEpochMicros() {
        return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Phase 3에서 실제 수집기(SnapShotData.h → proto 변환, grpc/ 쪽에 둘 것)로 교체될 더미 스냅샷들.
    sysmonitor::AgentData makeDummySys(const std::string& agentId) {
        sysmonitor::AgentData data;
        data.set_agent_id(agentId);
        sysmonitor::SysSnapshot* sys = data.mutable_sys();
        sys->set_timestamp_us(nowEpochMicros());
        sys->set_cpu_total(12.5);
        sys->set_mem_usage_percent(48.0);
        return data;
    }

    sysmonitor::AgentData makeDummyProc(const std::string& agentId) {
        sysmonitor::AgentData data;
        data.set_agent_id(agentId);
        sysmonitor::ProcSnapshot* proc = data.mutable_proc();
        proc->set_timestamp_us(nowEpochMicros());
        sysmonitor::ProcInfo* p = proc->add_procs();
        p->set_pid(1234);
        p->set_name("dummy.exe");
        p->set_cpu_usage(3.0);
        p->set_memory_mb(64.0);
        return data;
    }

    sysmonitor::AgentData makeDummyTarget(const std::string& agentId) {
        sysmonitor::AgentData data;
        data.set_agent_id(agentId);
        sysmonitor::TargetSnapshot* target = data.mutable_target();
        target->set_timestamp_us(nowEpochMicros());
        sysmonitor::TargetInfo* t = target->add_targets();
        t->set_name("dummy-target.exe");
        t->set_status(sysmonitor::TargetInfo::NEVER_SEEN);
        return data;
    }

    // 모든 RPC(Hello / StreamRealtime / StreamBatch)에 같은 신원 metadata를 싣는다 — 서버는 RPC마다 다시 확인한다.
    void addIdentity(grpc::ClientContext& ctx, const std::string& agentId, const std::string& apiKey, const std::string& instanceId) {
        ctx.AddMetadata("agent_id", agentId);
        ctx.AddMetadata("api_key", apiKey);
        ctx.AddMetadata("instance_id", instanceId);
    }

    // gRPC 상태 코드를 "호출부가 다음에 할 일" 기준의 ClientResult로 바꾼다.
    // Hello 결과와 스트림 Finish() 결과가 모두 이 함수를 거친다.
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

    // 스트림에 한 건을 쓴다. Write()가 실패하면 Finish()로 서버가 보낸 최종 상태(예: UNAUTHENTICATED)를
    // 회수해 로그로 남기고 스트림을 버린다. reset()해두면 closeStreams()가 같은 스트림에 Finish()를
    // 두 번 호출하지 않고, 이후 호출은 널 가드에 걸려 Disconnected를 반환한다.
    ClientResult writeOrFinish(const char* channel, std::unique_ptr<AgentDataWriter>& stream, const sysmonitor::AgentData& data) {
        if (!stream) {
            return ClientResult::Disconnected;   // 미연결 / connect() 실패 / 이미 끊긴 스트림
        }
        if (stream->Write(data)) {
            return ClientResult::Ok;
        }

        grpc::Status status = stream->Finish();
        stream.reset();
        spdlog::error("[GrpcClient] {} stream closed: code={} message=\"{}\"", channel, static_cast<int>(status.error_code()), status.error_message());

        // Write()가 실패했다면 상태가 OK로 오더라도 스트림은 이미 끝났다 — 재연결이 필요한 상태로 본다.
        ClientResult result = toClientResult(status);
        return result == ClientResult::Ok ? ClientResult::Disconnected : result;
    }
} // namespace

struct GrpcClient::Impl {
    std::shared_ptr<grpc::Channel> channel;
    std::unique_ptr<sysmonitor::AgentService::Stub> stub;

    grpc::ClientContext realtimeCtx;
    sysmonitor::Ack realtimeAck;
    std::unique_ptr<AgentDataWriter> realtimeStream;

    grpc::ClientContext batchCtx;
    sysmonitor::Ack batchAck;
    std::unique_ptr<AgentDataWriter> batchStream;
};

GrpcClient::GrpcClient(std::string serverUrl, std::string agentId, std::string apiKey, std::string instanceId)
    : impl_(std::make_unique<Impl>()), serverUrl_(std::move(serverUrl)), agentId_(std::move(agentId)), apiKey_(std::move(apiKey)), instanceId_(std::move(instanceId)) {}

GrpcClient::~GrpcClient() {
    closeStreams();
}

GrpcClient::GrpcClient(GrpcClient&&) noexcept = default;

void GrpcClient::closeStreams() {
    if (!impl_) {
        return;
    }
    if (impl_->realtimeStream) {
        impl_->realtimeStream->WritesDone();
        impl_->realtimeStream->Finish();
    }
    if (impl_->batchStream) {
        impl_->batchStream->WritesDone();
        impl_->batchStream->Finish();
    }
}

ClientResult GrpcClient::connect() {
    // connect()를 다시 호출하는 경우(예: Phase 4 재연결)를 대비한 정리.
    // 1) 기존에 열려 있던 스트림이 있으면 먼저 정상 종료한다
    // 2) grpc::ClientContext(realtimeCtx/batchCtx)는 한 번 RPC에 쓰이면 재사용할 수 없는 1회용
    //    객체라, Impl 전체를 새로 만들어 깨끗한 ClientContext로 다시 시작한다.
    closeStreams();
    impl_ = std::make_unique<Impl>();

    // Phase 1: 평문(insecure) 채널. Phase 2: agent_id/api_key를 call metadata로 실어 보낸다.
    // 서버는 스트림의 첫 메시지를 읽기 전에 이 metadata로 신원을 확인한다.
    impl_->channel = grpc::CreateChannel(serverUrl_, grpc::InsecureChannelCredentials());

    // gRPC 채널은 lazy하게 연결된다 — CreateChannel 시점엔 아직 TCP 연결을 시도조차 안 한
    // IDLE 상태다. WaitForConnected(true)가 연결 시도를 트리거하고, 실제로 READY(연결 성공)에
    // 도달할 때까지 최대 5초 대기한다. 이게 없으면 아래 stub->StreamXxx(...) 호출이 성공한
    // 것처럼 보여도(널이 아닌 포인터를 리턴) 실제로는 서버에 연결된 상태가 아닐 수 있다.
    if (!impl_->channel->WaitForConnected(std::chrono::system_clock::now() + std::chrono::seconds(5))) {
        spdlog::error("[GrpcClient] failed to reach {} within 5s", serverUrl_);
        return ClientResult::Disconnected;
    }

    impl_->stub = sysmonitor::AgentService::NewStub(impl_->channel);

    // 스트림을 열기 전에 Hello로 인증을 먼저 확인한다. 스트림은 인증이 거부돼도 첫 Write()가
    // 실패할 때까지 원인이 드러나지 않지만, unary RPC는 거부 사유를 즉시 Status로 돌려준다.
    // (서버는 스트림에서도 다시 인증하므로 이건 보안 장치가 아니라 빠르고 명확한 실패를 위한 것.)
    grpc::ClientContext helloCtx;
    addIdentity(helloCtx, agentId_, apiKey_, instanceId_);
    helloCtx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
    sysmonitor::HelloRequest helloReq;
    helloReq.set_protocol_version(sysmonitor::PROTOCOL_VERSION_CURRENT);   // 서버와 proto가 어긋나면 FAILED_PRECONDITION → Fatal
    sysmonitor::Ack helloAck;
    grpc::Status helloStatus = impl_->stub->Hello(&helloCtx, helloReq, &helloAck);
    if (!helloStatus.ok()) {
        spdlog::error("[GrpcClient] hello rejected by {}: code={} message=\"{}\"", serverUrl_, static_cast<int>(helloStatus.error_code()), helloStatus.error_message());
        return toClientResult(helloStatus);
    }
    spdlog::info("[GrpcClient] server says: {}", helloAck.message());

    // Phase 2: Agent 구별을 위한 metadata 추가 (서버가 스트림마다 다시 인증하고 세션을 확인한다)
    addIdentity(impl_->realtimeCtx, agentId_, apiKey_, instanceId_);
    addIdentity(impl_->batchCtx, agentId_, apiKey_, instanceId_);

    impl_->realtimeStream = impl_->stub->StreamRealtime(&impl_->realtimeCtx, &impl_->realtimeAck);
    impl_->batchStream = impl_->stub->StreamBatch(&impl_->batchCtx, &impl_->batchAck);

    // WaitForConnected()가 이미 실제 연결 성공을 확인했으므로, 여기서 null이 나오는 건
    // "서버 연결 실패"가 아니라 예상치 못한 내부 상태 이상이다 (마지막 방어선).
    if (!impl_->realtimeStream || !impl_->batchStream) {
        spdlog::error("[GrpcClient] unexpected null stream after successful connect to {}", serverUrl_);
        return ClientResult::Fatal;
    }

    spdlog::info("[GrpcClient] connected to {} as {}", serverUrl_, agentId_);
    return ClientResult::Ok;
}


ClientResult GrpcClient::sendRealtimeDummy() {
    if (!impl_) {
        return ClientResult::Disconnected;   // moved-from 객체
    }

    // 스냅샷 1건 = 메시지 1개. 하나라도 실패하면 스트림은 이미 버려졌으므로 나머지는 보내지 않는다.
    for (const sysmonitor::AgentData& data : { makeDummySys(agentId_), makeDummyProc(agentId_), makeDummyTarget(agentId_) }) {
        ClientResult result = writeOrFinish("realtime", impl_->realtimeStream, data);
        if (result != ClientResult::Ok) {
            return result;
        }
    }
    return ClientResult::Ok;
}

ClientResult GrpcClient::sendBatchDummy() {
    if (!impl_) {
        return ClientResult::Disconnected;   // moved-from 객체
    }

    // Phase 4-4 갭 전송 자리의 더미 — 배치 채널 연결 확인용으로 sys 스냅샷 1건만 보낸다.
    return writeOrFinish("batch", impl_->batchStream, makeDummySys(agentId_));
}
