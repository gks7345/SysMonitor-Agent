#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint> 
#include <cstdio>


// -------------------------------------------------------
// 세션 분석 결과 구조체
// -------------------------------------------------------
struct SessionSysSummary {
	std::string date;
	double avgCpuTotal = 0.0;
	double peakCpuTotal = 0.0;
	double avgMemUsagePercent = 0.0;
	double peakMemUsagePercent = 0.0;
	double avgDiskKBs = 0.0;
	double peakDiskKBs = 0.0;
	double avgNetKbps = 0.0;
	double peakNetKbps = 0.0;
	int    sampleCount = 0;
};

struct SessionProcSummary {
	std::string date;
	std::string procName;
	double avgCpuUsage = 0.0;
	double peakCpuUsage = 0.0;
	double avgMemoryMB = 0.0;
	double peakMemoryMB = 0.0;
	double avgDiskMBs = 0.0;
	double peakDiskMBs = 0.0;
	double avgNetMbps = 0.0;
	double peakNetMbps = 0.0;
	int    sampleCount = 0;
};

// 타겟 프로세스 요약
struct SessionTargetSummary {
	std::string date;
	std::string targetName;
	std::string exePath;

	double avgCpuUsage = 0.0;
	double peakCpuUsage = 0.0;
	double avgMemoryMB = 0.0;
	double peakMemoryMB = 0.0;
	double avgNetMbps = 0.0;
	double peakNetMbps = 0.0;

	uint32_t peakThreadCount = 0;
	uint32_t peakHandleCount = 0;
	double runTime = 0.0;
	double totalRuntime = 0.0;
	int    sampleCount = 0;

	bool hasData() const { return totalRuntime > 0.0 || runTime > 0.0; }
};