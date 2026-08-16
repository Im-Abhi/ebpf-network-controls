#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>

#include "control_plane.h"

namespace {

volatile std::sig_atomic_t g_running = 1;

void on_signal(int) {
    g_running = 0;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: agent <ifindex>" << std::endl;
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    int ifindex = std::atoi(argv[1]);
    ControlPlane plane;

    if (plane.init(ifindex) != 0) {
        std::cerr << "failed to attach eBPF programs to ifindex " << ifindex << std::endl;
        return 1;
    }

    std::cout << "control plane running on ifindex " << ifindex << std::endl;

    while (g_running) {
        for (const auto& event : plane.detect_attacks()) {
            std::cout << "event: " << event << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    plane.shutdown();
    std::cout << "control plane stopped" << std::endl;
    return 0;
}
