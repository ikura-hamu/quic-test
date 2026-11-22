#pragma once

#include <msquic.h>

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>

inline constexpr std::string_view protocol = "quic-test";
inline constexpr unsigned maxPayload = 4 * 1024 * 1024;
inline constexpr unsigned idleSeconds = 1200;

inline void check(QUIC_STATUS status, const char* operation) {
    if (QUIC_FAILED(status)) {
        char message[160];
        std::snprintf(message, sizeof(message), "%s failed (status=0x%x)", operation,
                      static_cast<unsigned>(status));
        throw std::runtime_error(message);
    }
}

inline unsigned number(std::string_view value, unsigned low, unsigned high, const char* name) {
    unsigned result = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result);
    if (error != std::errc{} || end != value.data() + value.size() ||
        result < low || result > high) {
        throw std::runtime_error(std::string(name) + " must be between " +
                                 std::to_string(low) + " and " + std::to_string(high));
    }
    return result;
}

inline const char* env(const char* name, const char* fallback) {
    if (const char* value = std::getenv(name); value && *value) {
        return value;
    }
    return fallback;
}

struct Quic {
    const QUIC_API_TABLE* api = nullptr;
    HQUIC registration = nullptr;
    HQUIC config = nullptr;

    Quic() = default;
    Quic(const Quic&) = delete;
    Quic& operator=(const Quic&) = delete;

    ~Quic() {
        if (config) api->ConfigurationClose(config);
        if (registration) api->RegistrationClose(registration);
        if (api) MsQuicClose(api);
    }

    void open(const QUIC_CREDENTIAL_CONFIG& credentials, bool server,
              std::string_view alpn = protocol) {
        check(MsQuicOpen2(&api), "MsQuicOpen2");
        const QUIC_REGISTRATION_CONFIG registrationConfig{
            "quic-paas-test", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
        check(api->RegistrationOpen(&registrationConfig, &registration), "RegistrationOpen");
        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs = idleSeconds * 1000;
        settings.IsSet.IdleTimeoutMs = TRUE;
        settings.HandshakeIdleTimeoutMs = 10000;
        settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
        settings.KeepAliveIntervalMs = 0;
        settings.IsSet.KeepAliveIntervalMs = TRUE;
        if (server) {
            settings.PeerBidiStreamCount = 1;
            settings.IsSet.PeerBidiStreamCount = TRUE;
            settings.SendBufferingEnabled = FALSE;
            settings.IsSet.SendBufferingEnabled = TRUE;
        }
        const QUIC_BUFFER buffer{static_cast<uint32_t>(alpn.size()),
                                 reinterpret_cast<uint8_t*>(const_cast<char*>(alpn.data()))};
        check(api->ConfigurationOpen(registration, &buffer, 1, &settings, sizeof(settings),
                                     nullptr, &config), "ConfigurationOpen");
        check(api->ConfigurationLoadCredential(config, &credentials), "ConfigurationLoadCredential");
    }
};
