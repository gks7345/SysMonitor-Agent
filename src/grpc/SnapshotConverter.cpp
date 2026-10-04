#include "grpc/SnapshotConverter.h"

#include <chrono>
#include <spdlog/spdlog.h>

namespace {
    // 스냅샷 timestamp 단위 — epoch 마이크로초 (DataStore::toTimestamp()와 같은 단위)
    int64_t toEpochMicros(std::chrono::system_clock::time_point tp) {
        return std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();
    }

    // default 없는 switch — TargetStatus에 값이 추가되면 C4062(/w14062)가 여기를 고치라고 알려 준다.
    sysmonitor::TargetInfo::Status toStatus(TargetStatus status) {
        switch (status) {
        case TargetStatus::RUNNING:     return sysmonitor::TargetInfo::RUNNING;
        case TargetStatus::NOT_RUNNING: return sysmonitor::TargetInfo::NOT_RUNNING;
        case TargetStatus::NEVER_SEEN:  return sysmonitor::TargetInfo::NEVER_SEEN;
        }
        // enum 정의 밖의 값(잘못된 캐스트 등) — 조용히 다른 상태로 바꾸지 않고 UNSPECIFIED로 보낸다.
        spdlog::warn("[SnapshotConverter] unknown target status {}", static_cast<int>(status));
        return sysmonitor::TargetInfo::STATUS_UNSPECIFIED;
    }

    void fillConnections(const std::vector<TargetNetConnection>& src, sysmonitor::TargetProcess* dst) {
        dst->mutable_connections()->Reserve(static_cast<int>(src.size()));
        for (const auto& c : src) {
            sysmonitor::NetConnection* conn = dst->add_connections();
            conn->set_protocol(c.protocol);
            conn->set_local_addr(c.localAddr);
            conn->set_remote_addr(c.remoteAddr);
            conn->set_state(c.state);
        }
    }

    // 메인 프로세스는 SnapshotTarget에, 자식은 SnapshotChildProcess에 같은 지표가 흩어져 있어 공통 부분을 여기서 채운다.
    // std::optional 필드는 값이 있을 때만 set한다 — 비어 있으면 필드를 보내지 않아 서버가 "수집하지 못함"으로 본다.
    // value_or(0)으로 채워 보내면 안 된다 (Phase 3 리뷰 High #5).
    template <typename T>
    void fillCommon(const T& src, sysmonitor::TargetProcess* dst) {
        dst->set_pid(src.pid);
        dst->set_cpu_usage(src.cpuUsage);
        if (src.memoryMB) dst->set_memory_mb(*src.memoryMB);
        dst->set_private_memory_mb(src.privateMemoryMB);
        dst->set_virtual_memory_mb(src.virtualMemoryMB);
        dst->set_disk_read_mbs(src.diskReadMBs);
        dst->set_disk_write_mbs(src.diskWriteMBs);
        dst->set_net_sent_mbps(src.netSentMbps);
        dst->set_net_recv_mbps(src.netRecvMbps);
        dst->set_thread_count(src.threadCount);
        dst->set_handle_count(src.handleCount);
        if (src.gdiObjectCount) dst->set_gdi_object_count(*src.gdiObjectCount);
        dst->set_page_fault_rate(src.pageFaultRate);
        fillConnections(src.connections, dst);
    }
} // namespace

namespace SnapshotConverter {

sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotSysData& src) {
    sysmonitor::AgentData data;
    data.set_agent_id(agentId);
    sysmonitor::SysSnapshot* sys = data.mutable_sys();
    sys->set_timestamp_us(toEpochMicros(src.timestamp));

    sys->set_cpu_total(src.cpu.cpuTotal);
    sys->set_cpu_freq_ghz(src.cpu.cpuFreqGHz);
    sys->set_cpu_user(src.cpu.cpuUser);
    sys->set_cpu_kernel(src.cpu.cpuKernel);
    sys->set_cpu_queue_length(src.cpu.cpuQueueLength);

    sys->set_mem_total_mb(src.mem.memTotalMB);
    sys->set_mem_usage_percent(src.mem.memUsagePercent);
    sys->set_mem_used_mb(src.mem.memUsedMB);
    sys->set_mem_avail_mb(src.mem.memAvailMB);
    sys->set_commit_mem_percent(src.mem.commitMemPercent);
    sys->set_committed_mem_gb(src.mem.committedMemGB);
    sys->set_commit_limit_gb(src.mem.commitLimitGB);

    sys->set_disk_read_kbs(src.disk.diskReadKBs);
    sys->set_disk_write_kbs(src.disk.diskWriteKBs);

    sys->set_net_sent_kbps(src.net.netSentKbps);
    sys->set_net_recv_kbps(src.net.netRecvKbps);
    return data;
}

sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotProcData& src) {
    sysmonitor::AgentData data;
    data.set_agent_id(agentId);
    sysmonitor::ProcSnapshot* proc = data.mutable_proc();
    proc->set_timestamp_us(toEpochMicros(src.timestamp));

    // 전체 목록을 그대로 보낸다 — TopN 개수/정렬 기준은 UI가 정한다 (기획노트 §2). src.topN은 쓰지 않는다.
    proc->mutable_procs()->Reserve(static_cast<int>(src.procs.size()));
    for (const auto& p : src.procs) {
        sysmonitor::ProcInfo* info = proc->add_procs();
        info->set_pid(p.procID);
        info->set_name(p.procName);
        info->set_cpu_usage(p.procCpuUsage);
        info->set_memory_mb(p.procMemoryMB);
        info->set_private_memory_mb(p.procPrivateMemoryMB);
        info->set_disk_read_mbs(p.procDiskReadMBs);
        info->set_disk_write_mbs(p.procDiskWriteMBs);
        info->set_net_sent_mbps(p.procNetSentMbps);
        info->set_net_recv_mbps(p.procNetRecvMbps);
    }
    return data;
}

sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotTargetData& src) {
    sysmonitor::AgentData data;
    data.set_agent_id(agentId);
    sysmonitor::TargetSnapshot* snap = data.mutable_target();
    snap->set_timestamp_us(toEpochMicros(src.timestamp));

    for (const auto& t : src.targets) {
        sysmonitor::TargetInfo* info = snap->add_targets();
        info->set_name(t.targetName);
        if (t.exePath) info->set_exe_path(*t.exePath);
        info->set_status(toStatus(t.status));

        if (info->status() == sysmonitor::TargetInfo::RUNNING) {
            // main / elapsed / children은 실행 중일 때만 (proto 주석과 같은 규칙)
            sysmonitor::TargetProcess* main = info->mutable_main();
            fillCommon(t, main);
            main->set_name(t.processName);   // 실제 실행 파일 이름(.exe 제외) — 대소문자가 등록 이름(info.name)과 다를 수 있다
            info->set_elapsed_sec(t.elapsedSec);

            info->mutable_children()->Reserve(static_cast<int>(t.children.size()));
            for (const auto& c : t.children) {
                sysmonitor::TargetProcess* child = info->add_children();
                fillCommon(c, child);
                child->set_name(c.processName);
            }
        }
        else if (info->status() == sysmonitor::TargetInfo::NOT_RUNNING) {
            // 마지막 세션 요약은 NOT_RUNNING일 때만 의미가 있다 (NEVER_SEEN은 데이터 없음)
            sysmonitor::LastSessionSummary* last = info->mutable_last_session();
            last->set_date(t.lastSessionDate);
            last->set_avg_cpu_usage(t.lastAvgCpuUsage);
            last->set_peak_cpu_usage(t.lastPeakCpuUsage);
            last->set_avg_memory_mb(t.lastAvgMemoryMB);
            last->set_peak_memory_mb(t.lastPeakMemoryMB);
            last->set_avg_net_mbps(t.lastAvgNetMbps);
            last->set_peak_net_mbps(t.lastPeakNetMbps);
            last->set_peak_thread_count(t.lastPeakThreadCount);
            last->set_peak_handle_count(t.lastPeakHandleCount);
            last->set_total_runtime_sec(t.lastTotalRuntimeSec);
        }
    }
    return data;
}

} // namespace SnapshotConverter
