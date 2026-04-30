#include <iostream>
#include <string>
#include <cstdint>
#include <print>

import sniffster.network.nicq_detector;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <interface>\n";
        return EXIT_FAILURE;
    }

    std::string interface = argv[1];

    std::println("[*] Initializing Sniffster on: {}", interface);

    // Initialize the detector from our module
    sniffster::nic_queue_detector detector(interface);

    // Detect the hardware parallelism available
    auto detected_q_count = detector.detect_queues();
    uint32_t q_count = detected_q_count.value_or(0);

    if (detected_q_count) {
        std::println("[+] Detected {} RX queue(s).", q_count);
    } else {
        std::println("[!] Queue detection failed.");
    }

    switch (q_count) {
        case 0:
            std::println("[!] Queue detection failed. Defaulting to single-queue mode.");
            q_count = 1; // Fallback to single queue if detection fails
            break;
        case 1:
            std::println("[!] Single-queue detected. Scaling restricted to one core.");
            break;
        default:
            std::println("[+] Parallel mode active. Ready to spawn {} handlers.", q_count);
    }

    // Next step in your pipeline:
    // for (uint32_t i = 0; i < q_count; ++i) {
    //     spawn_handler_on_core(i, interface);
    // }

    return 0;
}
