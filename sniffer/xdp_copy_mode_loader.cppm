module;

#include <cstdint>
#include <format>
#include <string>
#include <utility>
#include <vector>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sniffer/xdp_copy_mode.skel.h"

export module sniffster.bpf_loader.xdp_copy_mode_loader;

import sniffster.platform;
import sniffster.platform.decorated_throw;
import sniffster.network.config;
import sniffster.threading_config;

export namespace sniffster {

class xdp_copy_mode_loader {
public:
    explicit xdp_copy_mode_loader(const network_interface& interface) :
            interface_(interface) {
        try {
            load_bpf();
            attach_bpf_to_nic();
        } catch (...) {
            release_bpf_();
            throw;
        }
    }

    ~xdp_copy_mode_loader() {
        release_bpf_();
    }

    xdp_copy_mode_loader(const xdp_copy_mode_loader&) = delete;
    xdp_copy_mode_loader& operator=(const xdp_copy_mode_loader&) = delete;

    xdp_copy_mode_loader(xdp_copy_mode_loader&&) = delete;
    xdp_copy_mode_loader& operator=(xdp_copy_mode_loader&&) = delete;

    int perf_map_fd() const {
        if (!is_loaded_ || !skel_) {
            platform::throw_runtime_error("xdp_copy_mode_loader is not loaded");
        }

        return bpf_map__fd(skel_->maps.perf_map);
    }

protected:
    void load_bpf() {
        skel_ = xdp_copy_mode_bpf__open();
        if (!skel_) {
            platform::throw_runtime_error("Failed to open BPF skeleton");
        }

        const uint32_t cpu_count_(platform::detect_cpu_count());
        
        const int resize_err = bpf_map__set_max_entries(skel_->maps.perf_map, cpu_count_);
        if (resize_err != 0) {
            platform::throw_runtime_error("Failed to size perf map for host CPU count");
        }

        const int load_err = xdp_copy_mode_bpf__load(skel_);
        if (load_err != 0) {
            platform::throw_runtime_error("Failed to load BPF skeleton into the kernel");
        }

        is_loaded_ = true;
    }

    void attach_bpf_to_nic() {
        uint32_t flags = 0;
        const int err = bpf_xdp_attach(
            interface_.ifindex,
            bpf_program__fd(skel_->progs.xdp_copy_handle_packet),
            flags,
            nullptr
        );

        if (err) {
            platform::throw_runtime_error(std::format("Failed to attach XDP to {}",
                                                      interface_.name));
        }

        attached_flags_ = flags;
        is_attached_ = true;
    }

    void detach_bpf_from_nic() {
        if (is_attached_) {
            bpf_xdp_detach(interface_.ifindex, attached_flags_, nullptr);
            is_attached_ = false;
        }
    }

private:
    void release_bpf_() noexcept {
        if (!skel_) {
            return;
        }

        detach_bpf_from_nic();
        xdp_copy_mode_bpf__destroy(skel_);
        skel_ = nullptr;
        is_loaded_ = false;
    }

    network_interface interface_;
    uint32_t attached_flags_ = 0;
    bool is_attached_ = false;
    bool is_loaded_ = false;
    struct xdp_copy_mode_bpf* skel_ = nullptr;
};

} // namespace sniff
