#include "AgentConfig.h"

#include <cstdlib>

#include <INIReader.h>
#include <spdlog/spdlog.h>

#include "Config.h"

namespace {

// INIReader는 같은 섹션의 같은 키가 여러 번 나오면 값을 '\n'으로 이어 붙인다 (INIReader::ValueHandler).
bool isDuplicated(const INIReader& r, const char* sec, const char* key) {
    return r.Get(sec, key, "").find('\n') != std::string::npos;
}

const char* duplicateNote(const INIReader& r, const char* sec, const char* key) {
    return isDuplicated(r, sec, key) ? " (key appears more than once)" : "";
}

// 경고에 원문을 넣을 때 중복 키의 '\n'이 로그 한 줄을 둘로 쪼개지 않도록 "\n" 두 글자로 바꾼다.
std::string forLog(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        if (c == '\n') {
            out += "\\n";
        } else {
            out += c;
        }
    }
    return out;
}

// 아래 read*()는 "키는 있는데 값을 해석할 수 없음"을 경고하고 기본값을 쓴다 (문법 오류 줄과 같은 규칙).
// 키가 아예 없으면 경고 없이 기본값 — 파일이 없거나 생략한 경우라 정상이다.

bool readBool(const INIReader& r, const std::string& path, const char* sec, const char* key, bool def) {
    if (!r.HasValue(sec, key)) {
        return def;
    }
    // GetBoolean()은 true/yes/on/1, false/no/off/0 외의 값에 기본값을 돌려준다 —
    // 기본값을 바꿔 두 번 읽어 결과가 다르면 해석되지 않은 값이다 (inih의 해석 규칙을 복제하지 않기 위함).
    if (r.GetBoolean(sec, key, true) != r.GetBoolean(sec, key, false)) {
        spdlog::warn("[AgentConfig] {}: [{}] {} = \"{}\" is not a boolean{} — using default {}", path, sec, key, forLog(r.Get(sec, key, "")), duplicateNote(r, sec, key), def);
        return def;
    }
    return r.GetBoolean(sec, key, def);
}

long readInt(const INIReader& r, const std::string& path, const char* sec, const char* key, long def) {
    if (!r.HasValue(sec, key)) {
        return def;
    }
    // GetInteger()는 strtol로 앞쪽 숫자만 읽어 "2일"을 2로, "48\n24"(중복)를 48로 만든다 —
    // 쓰지 않고 원문 전체가 숫자인지 직접 확인한다.
    const std::string raw = r.Get(sec, key, "");
    char* end = nullptr;
    const long n = std::strtol(raw.c_str(), &end, 10);
    if (raw.empty() || *end != '\0') {
        spdlog::warn("[AgentConfig] {}: [{}] {} = \"{}\" is not an integer{} — using default {}", path, sec, key, forLog(raw), duplicateNote(r, sec, key), def);
        return def;
    }
    return n;
}

// 문자열은 형식 검사가 없으므로 중복(값에 '\n')만 확인한다. api_key가 올 수 있으므로 값은 로그에 남기지 않는다.
std::string readString(const INIReader& r, const std::string& path, const char* sec, const char* key, const std::string& def) {
    if (!r.HasValue(sec, key)) {
        return def;
    }
    if (isDuplicated(r, sec, key)) {
        spdlog::warn("[AgentConfig] {}: [{}] {} appears more than once — using default", path, sec, key);
        return def;
    }
    return r.Get(sec, key, def);
}

} // namespace

std::optional<AgentConfig> AgentConfig::load(const std::string& iniPath) {
    INIReader reader(iniPath);

    // ParseError(): 0 = 정상, 음수 = 파일을 열 수 없음, 양수 N = N번째 줄 문법 오류.
    // inih는 문법 오류가 난 줄만 건너뛰고 나머지 줄은 계속 읽으므로(INI_STOP_ON_FIRST_ERROR=0),
    // 틀린 줄의 설정은 아래 read*()의 기본값(Config::)으로 자연스럽게 폴백한다.
    if (reader.ParseError() < 0) {
        spdlog::warn("[AgentConfig] {} not found, falling back to defaults (send_to_server=false)", iniPath);
    } else if (reader.ParseError() > 0) {
        spdlog::warn("[AgentConfig] {} line {}: syntax error (expected 'key = value') — line ignored, its setting falls back to default (only the first error line is reported)", iniPath, reader.ParseError());
    }

    AgentConfig cfg;

    // agent.ini의 값이 우선한다. 마지막 인자(Config::)는 파일/키가 없거나 값을 해석할 수 없을 때만 쓰인다.
    cfg.sendToServer = readBool(reader, iniPath, "server", "send_to_server", Config::SEND_TO_SERVER);
    cfg.serverUrl = readString(reader, iniPath, "server", "url", Config::SERVER_URL);
    cfg.agentId = readString(reader, iniPath, "agent", "id", Config::AGENT_ID);
    cfg.apiKey = readString(reader, iniPath, "agent", "api_key", "");
    cfg.localBufferHours = static_cast<int>(readInt(reader, iniPath, "agent", "local_buffer_hours", Config::LOCAL_BUFFER_HOURS));

    // url 기본값(localhost)은 "ini 파일 자체가 없는" 경우를 위한 값이고, 그때는 send_to_server도 false라 쓰이지 않는다.
    // 운영자가 서버 전송을 켰는데 url을 쓸 수 없다면(줄 누락/문법 오류/빈 값/중복) localhost로 대신 붙지 않고 멈춘다 —
    // 로컬에 다른 서버가 떠 있으면 엉뚱한 서버에 "정상적으로" 연결되어 원인을 알 수 없게 되기 때문이다.
    const std::string rawUrl = reader.Get("server", "url", "");
    if (cfg.sendToServer && (rawUrl.empty() || rawUrl.find('\n') != std::string::npos)) {
        spdlog::error("[AgentConfig] {}: send_to_server=true but [server] url is missing, empty, malformed or duplicated — refusing to fall back to {}", iniPath, Config::SERVER_URL);
        return std::nullopt;
    }

    // 틀린 줄/값이 있었다면 어떤 값이 기본값으로 바뀌었는지 알 수 있도록, 실제 적용된 값을 항상 남긴다.
    spdlog::info("[AgentConfig] effective config from {}: agent_id={}, send_to_server={}, url={}, local_buffer_hours={}", iniPath, cfg.agentId, cfg.sendToServer, cfg.serverUrl, cfg.localBufferHours);
    return cfg;
}
