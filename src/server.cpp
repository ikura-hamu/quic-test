#include "common.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <memory>
#include <poll.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr std::string_view probePrefix = "QUIC-PROBE/1 ";
constexpr size_t probeLength = probePrefix.size() + 32;
constexpr QUIC_UINT62 echoError = 1;

struct Server {
    Quic quic;
    std::atomic<unsigned long> nextConnection{1};
};

struct Connection {
    Server& server;
    unsigned long id;
};

struct Stream {
    const QUIC_API_TABLE* api;
    unsigned long connectionId;
    QUIC_UINT62 id;
    uint64_t received = 0;
};

struct Send {
    explicit Send(size_t size) : bytes(size), buffer{static_cast<uint32_t>(size), bytes.data()} {}
    std::vector<uint8_t> bytes;
    QUIC_BUFFER buffer;
};

QUIC_STATUS QUIC_API streamCallback(HQUIC handle, void* context, QUIC_STREAM_EVENT* event) {
    auto& stream = *static_cast<Stream*>(context);
    switch (event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE: {
        const auto& receive = event->RECEIVE;
        if (receive.TotalBufferLength == 0) break;
        if (receive.TotalBufferLength > maxPayload - stream.received) {
            std::printf("[WARN] conn=%lu stream=%llu Payload exceeds %u bytes\n",
                        stream.connectionId, static_cast<unsigned long long>(stream.id), maxPayload);
            stream.api->StreamShutdown(handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, echoError);
            break;
        }
        try {
            auto send = std::make_unique<Send>(receive.TotalBufferLength);
            size_t offset = 0;
            for (uint32_t i = 0; i < receive.BufferCount; ++i) {
                const auto& buffer = receive.Buffers[i];
                std::memcpy(send->bytes.data() + offset, buffer.Buffer, buffer.Length);
                offset += buffer.Length;
            }
            check(stream.api->StreamSend(handle, &send->buffer, 1, QUIC_SEND_FLAG_NONE,
                                         send.get()), "StreamSend");
            send.release();
            stream.received += receive.TotalBufferLength;
        } catch (const std::exception& error) {
            std::printf("[WARN] conn=%lu Echo failed (%s)\n", stream.connectionId, error.what());
            stream.api->StreamShutdown(handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, echoError);
        }
        break;
    }
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        delete static_cast<Send*>(event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        std::printf("[INFO] conn=%lu stream=%llu Received %llu bytes\n", stream.connectionId,
                    static_cast<unsigned long long>(stream.id),
                    static_cast<unsigned long long>(stream.received));
        stream.api->StreamShutdown(handle, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;
    case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
        if (event->SEND_SHUTDOWN_COMPLETE.Graceful) {
            std::printf("[INFO] conn=%lu stream=%llu Sent %llu bytes\n", stream.connectionId,
                        static_cast<unsigned long long>(stream.id),
                        static_cast<unsigned long long>(stream.received));
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        stream.api->StreamShutdown(handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, echoError);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        stream.api->StreamClose(handle);
        delete &stream;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API connectionCallback(HQUIC handle, void* context, QUIC_CONNECTION_EVENT* event) {
    auto& connection = *static_cast<Connection*>(context);
    const auto* api = connection.server.quic.api;
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        std::printf("[INFO] conn=%lu Handshake completed ALPN=%.*s\n", connection.id,
                    event->CONNECTED.NegotiatedAlpnLength,
                    reinterpret_cast<const char*>(event->CONNECTED.NegotiatedAlpn));
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
        const auto& peer = event->PEER_STREAM_STARTED;
        auto stream = std::unique_ptr<Stream>(new (std::nothrow) Stream{api, connection.id, 0});
        if (!stream) return QUIC_STATUS_OUT_OF_MEMORY;
        uint32_t length = sizeof(stream->id);
        const auto status = api->GetParam(peer.Stream, QUIC_PARAM_STREAM_ID, &length, &stream->id);
        if (QUIC_FAILED(status)) return status;
        std::printf("[INFO] conn=%lu stream=%llu Bidirectional stream opened\n", connection.id,
                    static_cast<unsigned long long>(stream->id));
        api->SetCallbackHandler(peer.Stream, reinterpret_cast<void*>(streamCallback), stream.get());
        stream.release();
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        std::printf("[WARN] conn=%lu Transport shutdown status=0x%x code=0x%llx\n", connection.id,
                    static_cast<unsigned>(event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status),
                    static_cast<unsigned long long>(event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode));
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        std::printf("[INFO] conn=%lu Connection closed handshake=%u\n", connection.id,
                    static_cast<unsigned>(event->SHUTDOWN_COMPLETE.HandshakeCompleted));
        api->ConnectionClose(handle);
        delete &connection;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API listenerCallback(HQUIC, void* context, QUIC_LISTENER_EVENT* event) {
    if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) return QUIC_STATUS_SUCCESS;
    auto& server = *static_cast<Server*>(context);
    const auto& incoming = event->NEW_CONNECTION;
    auto connection = std::unique_ptr<Connection>(
        new (std::nothrow) Connection{server, server.nextConnection++});
    if (!connection) return QUIC_STATUS_OUT_OF_MEMORY;

    QUIC_ADDR_STR local{}, remote{};
    QuicAddrToString(incoming.Info->LocalAddress, &local);
    QuicAddrToString(incoming.Info->RemoteAddress, &remote);
    std::printf("[INFO] conn=%lu New connection local=%s peer=%s\n", connection->id,
                local.Address, remote.Address);
    server.quic.api->SetCallbackHandler(incoming.Connection,
                                       reinterpret_cast<void*>(connectionCallback), connection.get());
    const auto status = server.quic.api->ConnectionSetConfiguration(incoming.Connection,
                                                                   server.quic.config);
    if (QUIC_SUCCEEDED(status)) connection.release();
    return status;
}

void runQuic(uint16_t port, const sigset_t& signals) {
    std::printf("[INFO] QUIC server starting instance=%s\n", env("HOSTNAME", "unknown"));
    QUIC_CERTIFICATE_FILE files{env("QUIC_KEY", "/certs/server.key"),
                                env("QUIC_CERT", "/certs/server.crt")};
    QUIC_CREDENTIAL_CONFIG credentials{};
    credentials.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    credentials.CertificateFile = &files;
    Server server;
    server.quic.open(credentials, true);

    HQUIC listener = nullptr;
    check(server.quic.api->ListenerOpen(server.quic.registration, listenerCallback, &server,
                                        &listener), "ListenerOpen");
    QUIC_ADDR address{};
    QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&address, port);
    const QUIC_BUFFER alpn{static_cast<uint32_t>(protocol.size()),
                          reinterpret_cast<uint8_t*>(const_cast<char*>(protocol.data()))};
    const auto status = server.quic.api->ListenerStart(listener, &alpn, 1, &address);
    if (QUIC_SUCCEEDED(status)) {
        std::printf("[INFO] Listening on UDP 0.0.0.0:%u ALPN=%s\n", port, protocol.data());
        std::puts("[INFO] QUIC listener started");
        int signal = 0;
        sigwait(&signals, &signal);
    }
    server.quic.api->ListenerClose(listener);
    server.quic.api->RegistrationShutdown(server.quic.registration,
                                           QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    check(status, "ListenerStart");
}

int serveProbe(int fd, int signalFd, uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        std::perror("bind");
        return 1;
    }
    std::printf("[INFO] UDP probe listening on 0.0.0.0:%u\n", port);
    pollfd sockets[]{{fd, POLLIN, 0}, {signalFd, POLLIN, 0}};
    while (true) {
        if (poll(sockets, 2, -1) < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            return 1;
        }
        if (sockets[1].revents & POLLIN) return 0;
        std::array<char, probeLength + 1> bytes{};
        sockaddr_in peer{};
        socklen_t length = sizeof(peer);
        const auto size = recvfrom(fd, bytes.data(), bytes.size(), 0,
                                   reinterpret_cast<sockaddr*>(&peer), &length);
        if (size != probeLength || std::string_view(bytes.data(), probePrefix.size()) != probePrefix) {
            continue;
        }
        const std::string_view nonce(bytes.data() + probePrefix.size(), 32);
        if (nonce.find_first_not_of("0123456789abcdef") != std::string_view::npos) continue;
        char peerIp[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &peer.sin_addr, peerIp, sizeof(peerIp));
        std::printf("[PASS] UDP packet received nonce=%.*s peer=%s:%u\n",
                    static_cast<int>(nonce.size()), nonce.data(), peerIp, ntohs(peer.sin_port));
        if (sendto(fd, bytes.data(), size, 0, reinterpret_cast<sockaddr*>(&peer), length) < 0) {
            std::perror("sendto");
        }
    }
}

} // namespace


int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::puts("Usage: quic-server [--udp-probe]\n"
                  "Environment: QUIC_PORT (4433), QUIC_CERT (/certs/server.crt), "
                  "QUIC_KEY (/certs/server.key)");
        return 0;
    }
    try {
        const bool probe = argc == 2 && std::string_view(argv[1]) == "--udp-probe";
        if (argc != 1 && !probe) throw std::runtime_error("see --help");
        const auto port = static_cast<uint16_t>(number(env("QUIC_PORT", "4433"), 1, 65535,
                                                       "QUIC_PORT"));
        sigset_t signals{};
        sigemptyset(&signals);
        sigaddset(&signals, SIGTERM);
        sigaddset(&signals, SIGINT);
        if (pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0) {
            throw std::runtime_error("pthread_sigmask failed");
        }
        if (!probe) {
            runQuic(port, signals);
            return 0;
        }
        const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        const int signalFd = signalfd(-1, &signals, SFD_CLOEXEC);
        const int result = fd < 0 || signalFd < 0 ? 1 : serveProbe(fd, signalFd, port);
        if (fd < 0 || signalFd < 0) std::perror("socket/signalfd");
        if (fd >= 0) close(fd);
        if (signalFd >= 0) close(signalFd);
        return result;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "[FAIL] %s\n", error.what());
        return 1;
    }
}
