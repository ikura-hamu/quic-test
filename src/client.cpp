#include "common.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

struct Options {
    std::string host;
    std::string ca;
    std::string alpn{protocol};
    unsigned port = 4433;
    unsigned bytes = 5;
    unsigned connections = 1;
    unsigned repeat = 1;
    unsigned hold = 0;
    unsigned interval = 15;
};

void help() {
    std::puts(
        "Usage: quic-client HOST [OPTIONS]\n"
        "  --port N          Remote UDP port (4433)\n"
        "  --ca FILE         PEM CA for private test certificates (system trust by default)\n"
        "  --alpn NAME       ALPN to require (quic-test)\n"
        "  --bytes N         Bytes per stream (5, 'hello'; max 4194304)\n"
        "  --connections N   Simultaneous connections per round (1-100)\n"
        "  --repeat N        Rounds of fresh connections (1-100)\n"
        "  --hold N          Seconds to keep each original connection (0-1100)\n"
        "  --interval N      Echo interval during hold (15); 0 means idle until final echo");
}

Options parse(int argc, char** argv) {
    if (argc < 2 || std::string_view(argv[1]).starts_with("--")) {
        throw std::runtime_error("HOST is required (see --help)");
    }
    Options options;
    options.host = argv[1];
    for (int i = 2; i < argc; ++i) {
        const std::string_view option = argv[i];
        if (++i == argc) throw std::runtime_error(std::string(option) + " needs a value");
        const std::string_view value = argv[i];
        if (option == "--port") options.port = number(value, 1, 65535, "port");
        else if (option == "--ca") options.ca = value;
        else if (option == "--alpn") options.alpn = value;
        else if (option == "--bytes") options.bytes = number(value, 1, maxPayload, "bytes");
        else if (option == "--connections") options.connections = number(value, 1, 100, "connections");
        else if (option == "--repeat") options.repeat = number(value, 1, 100, "repeat");
        else if (option == "--hold") options.hold = number(value, 0, 1100, "hold");
        else if (option == "--interval") options.interval = number(value, 0, 1100, "interval");
        else throw std::runtime_error("unknown option " + std::string(option));
    }
    if (options.alpn.empty() || options.alpn.size() > 255) {
        throw std::runtime_error("ALPN length must be 1-255 bytes");
    }
    return options;
}

struct Stream {
    const QUIC_API_TABLE* api;
    const std::vector<uint8_t>& expected;
    HQUIC handle = nullptr;
    QUIC_BUFFER sendBuffer;
    std::mutex mutex;
    std::condition_variable changed;
    size_t received = 0;
    bool fin = false;
    bool complete = false;
    bool valid = true;
    QUIC_STATUS transportStatus = QUIC_STATUS_SUCCESS;

    Stream(const QUIC_API_TABLE* api, std::vector<uint8_t>& bytes)
        : api(api), expected(bytes),
          sendBuffer{static_cast<uint32_t>(bytes.size()), bytes.data()} {}

    ~Stream() {
        if (handle) api->StreamClose(handle);
    }

    static QUIC_STATUS QUIC_API callback(HQUIC, void* context, QUIC_STREAM_EVENT* event) {
        auto& stream = *static_cast<Stream*>(context);
        const std::lock_guard lock(stream.mutex);
        switch (event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
                const auto& part = event->RECEIVE.Buffers[i];
                if (part.Length > stream.expected.size() - stream.received ||
                    (part.Length && std::memcmp(part.Buffer, stream.expected.data() + stream.received,
                                                part.Length) != 0)) {
                    stream.valid = false;
                    break;
                }
                stream.received += part.Length;
            }
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            stream.fin = true;
            break;
        case QUIC_STREAM_EVENT_START_COMPLETE:
            stream.transportStatus = event->START_COMPLETE.Status;
            stream.valid &= QUIC_SUCCEEDED(stream.transportStatus);
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            stream.valid &= !event->SEND_COMPLETE.Canceled;
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            stream.valid = false;
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            if (event->SHUTDOWN_COMPLETE.ConnectionShutdown) {
                stream.transportStatus = event->SHUTDOWN_COMPLETE.ConnectionCloseStatus;
                stream.valid = false;
            }
            stream.complete = true;
            break;
        default:
            break;
        }
        stream.changed.notify_one();
        return QUIC_STATUS_SUCCESS;
    }

    void exchange(HQUIC connection) {
        check(api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, callback, this, &handle),
              "StreamOpen");
        check(api->StreamStart(handle, QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL), "StreamStart");
        check(api->StreamSend(handle, &sendBuffer, 1, QUIC_SEND_FLAG_FIN, nullptr), "StreamSend");
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, 30s, [this] { return !valid || complete; })) {
            throw std::runtime_error("Echo timed out");
        }
        check(transportStatus, "Echo transport");
        if (!valid || !fin || received != expected.size()) {
            throw std::runtime_error("Echo length, contents, or graceful stream close did not match");
        }
    }
};

struct Connection {
    Quic& quic;
    const Options& options;
    HQUIC handle = nullptr;
    std::mutex mutex;
    std::condition_variable changed;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    QUIC_UINT62 errorCode = 0;
    bool connected = false;
    bool expectedAlpn = false;
    bool closing = false;
    bool complete = false;

    Connection(Quic& quic, const Options& options) : quic(quic), options(options) {}

    ~Connection() {
        if (handle) quic.api->ConnectionClose(handle);
    }

    static QUIC_STATUS QUIC_API callback(HQUIC, void* context, QUIC_CONNECTION_EVENT* event) {
        auto& connection = *static_cast<Connection*>(context);
        const std::lock_guard lock(connection.mutex);
        switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            const auto& negotiated = event->CONNECTED;
            connection.connected = true;
            connection.expectedAlpn = std::string_view(
                reinterpret_cast<const char*>(negotiated.NegotiatedAlpn),
                negotiated.NegotiatedAlpnLength) == connection.options.alpn;
            break;
        }
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            connection.status = event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
            connection.errorCode = event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
            connection.closing = true;
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            connection.errorCode = event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
            connection.closing = true;
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            connection.closing = true;
            connection.complete = true;
            break;
        default:
            break;
        }
        connection.changed.notify_one();
        return QUIC_STATUS_SUCCESS;
    }

    void start() {
        check(quic.api->ConnectionOpen(quic.registration, callback, this, &handle), "ConnectionOpen");
        check(quic.api->ConnectionStart(handle, quic.config, QUIC_ADDRESS_FAMILY_INET,
                                        options.host.c_str(), static_cast<uint16_t>(options.port)),
              "ConnectionStart");
    }

    void requireOpen(const char* stage) const {
        if (closing) {
            char details[160];
            std::snprintf(details, sizeof(details), "%s: connection closed (status=0x%x code=0x%llx)",
                          stage, static_cast<unsigned>(status),
                          static_cast<unsigned long long>(errorCode));
            throw std::runtime_error(details);
        }
    }

    void handshake() {
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, 15s, [this] { return connected || closing; })) {
            throw std::runtime_error("Handshake timed out");
        }
        requireOpen("Handshake");
        if (!expectedAlpn) throw std::runtime_error("Unexpected negotiated ALPN");
    }

    void waitUntil(Clock::time_point time) {
        std::unique_lock lock(mutex);
        changed.wait_until(lock, time, [this] { return closing; });
        requireOpen("Connection hold");
    }

    void shutdown() {
        quic.api->ConnectionShutdown(handle, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, 10s, [this] { return complete; })) {
            throw std::runtime_error("Connection shutdown timed out");
        }
    }
};

std::vector<uint8_t> payload(unsigned length, unsigned seed) {
    if (length == 5) return {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> bytes(length);
    for (unsigned i = 0; i < length; ++i) {
        bytes[i] = static_cast<uint8_t>((i * 31u) ^ (i >> 8) ^ seed);
    }
    return bytes;
}

void exchange(Connection& connection, std::vector<uint8_t>& bytes) {
    Stream stream(connection.quic.api, bytes);
    stream.exchange(connection.handle);
}

template<typename Work>
void forEachConnection(const std::vector<std::unique_ptr<Connection>>& connections, Work work) {
    std::vector<std::future<void>> jobs;
    for (size_t i = 0; i < connections.size(); ++i) {
        jobs.push_back(std::async(std::launch::async, [&, i] {
            try {
                work(*connections[i], static_cast<unsigned>(i));
            } catch (const std::exception& error) {
                throw std::runtime_error("connection " + std::to_string(i + 1) + ": " + error.what());
            }
        }));
    }
    for (auto& job : jobs) job.get();
}

void run(Quic& quic, const Options& options) {
    for (unsigned round = 1; round <= options.repeat; ++round) {
        std::printf("[INFO] Round %u/%u, connecting to %s UDP/%u (%u connections)\n",
                    round, options.repeat, options.host.c_str(), options.port, options.connections);
        std::vector<std::unique_ptr<Connection>> connections;
        for (unsigned i = 0; i < options.connections; ++i) {
            auto connection = std::make_unique<Connection>(quic, options);
            connection->start();
            connections.push_back(std::move(connection));
        }
        forEachConnection(connections, [](Connection& connection, unsigned) { connection.handshake(); });
        std::puts("[PASS] QUIC handshake completed");
        std::printf("[PASS] Custom ALPN negotiated (%s)\n", options.alpn.c_str());

        forEachConnection(connections, [&](Connection& connection, unsigned index) {
            auto bytes = payload(options.bytes, index + round);
            exchange(connection, bytes);
        });
        std::puts("[PASS] Bidirectional stream opened");
        std::printf("[PASS] Echo response received (%u bytes per connection, contents matched)\n",
                    options.bytes);

        if (options.hold) {
            const auto start = Clock::now();
            const auto end = start + std::chrono::seconds(options.hold);
            std::printf("[INFO] Holding the same connections for %u seconds (interval=%u)\n",
                        options.hold, options.interval);
            forEachConnection(connections, [&](Connection& connection, unsigned) {
                auto hello = payload(5, 0);
                if (options.interval) {
                    const auto interval = std::chrono::seconds(options.interval);
                    for (auto next = start + interval; next < end; next = Clock::now() + interval) {
                        connection.waitUntil(next);
                        exchange(connection, hello);
                    }
                }
                connection.waitUntil(end);
                exchange(connection, hello);
            });
            if (options.hold == 600) std::puts("[PASS] Connection maintained for 10 minutes");
            else std::printf("[PASS] Connection maintained for %u seconds\n", options.hold);
        }
        forEachConnection(connections, [](Connection& connection, unsigned) { connection.shutdown(); });
        if (options.connections > 1) {
            std::printf("[PASS] %u simultaneous connections completed\n", options.connections);
        }
    }
    if (options.repeat > 1) {
        std::printf("[PASS] Reconnection completed (%u fresh rounds)\n", options.repeat);
    }
}

} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        help();
        return 0;
    }
    try {
        const auto options = parse(argc, argv);
        QUIC_CREDENTIAL_CONFIG credentials{};
        credentials.Type = QUIC_CREDENTIAL_TYPE_NONE;
        credentials.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (!options.ca.empty()) {
            credentials.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
            credentials.CaCertificateFile = options.ca.c_str();
        }
        Quic quic;
        quic.open(credentials, false, options.alpn);
        run(quic, options);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[FAIL] %s\n", error.what());
        return 1;
    }
}
