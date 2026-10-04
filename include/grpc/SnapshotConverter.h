#pragma once

#include <string>

#include "models/SnapShotData.h"
#include "sysmonitor.pb.h"

// 수집기 스냅샷(models/SnapShotData.h) → proto AgentData 변환 (기획노트 Phase 3-2).
// SysMonitorAgentCore가 proto에 의존하지 않도록 변환은 exe 타깃(grpc/)에만 둔다.
// 모든 string 필드는 수집기가 이미 UTF-8로 채운 값이다 (Phase 3-0, util/StrUtil.h).
namespace SnapshotConverter {
    sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotSysData& sys);
    sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotProcData& proc);
    sysmonitor::AgentData toAgentData(const std::string& agentId, const SnapshotTargetData& target);
}
