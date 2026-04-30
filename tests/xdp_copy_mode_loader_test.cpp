#include <cstdint>
#include <cstdlib>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

import sniffster.bpf_loader.xdp_copy_mode_loader;
import sniffster.network.config;

namespace {

struct FakeLoaderState {
    int open_skeleton_result = 0;
    int load_skeleton_result = 0;
    int set_max_entries_result = 0;
    int attach_result = 0;
    int map_fd_result = 17;
    int program_fd_result = 23;

    int open_skeleton_calls = 0;
    int load_skeleton_calls = 0;
    int destroy_skeleton_calls = 0;
    int set_max_entries_calls = 0;
    int attach_calls = 0;
    int detach_calls = 0;
    int map_fd_calls = 0;
    int program_fd_calls = 0;

    int last_attach_ifindex = -1;
    int last_attach_prog_fd = -1;
    std::uint32_t last_attach_flags = 0;
    int last_detach_ifindex = -1;
    std::uint32_t last_detach_flags = 0;
    std::uint32_t last_max_entries = 0;
    bpf_map* perf_map = reinterpret_cast<bpf_map*>(0x100);
    bpf_program* program = reinterpret_cast<bpf_program*>(0x200);
};

FakeLoaderState g_loader;

struct FakeIfaddrsEntry {
    ifaddrs node{};
    sockaddr_in addr{};
    sockaddr_in netmask{};
    std::string name;
};

struct FakeIfaddrsState {
    std::vector<std::pair<std::string, unsigned int>> indices;
    std::vector<FakeIfaddrsEntry> entries;
    ifaddrs* head = nullptr;
    int freeifaddrs_calls = 0;

    void rebuild_links() {
        head = entries.empty() ? nullptr : &entries.front().node;

        for (std::size_t i = 0; i < entries.size(); ++i) {
            auto& entry = entries[i];
            entry.node = {};
            entry.node.ifa_name = entry.name.data();
            entry.node.ifa_addr = reinterpret_cast<sockaddr*>(&entry.addr);
            entry.node.ifa_netmask = reinterpret_cast<sockaddr*>(&entry.netmask);
            entry.node.ifa_next = (i + 1 < entries.size()) ? &entries[i + 1].node : nullptr;
        }
    }

    void add_ipv4(std::string ifname, std::uint32_t ip_host_order, std::uint32_t netmask_host_order) {
        auto& entry = entries.emplace_back();
        entry.name = std::move(ifname);
        entry.addr.sin_family = AF_INET;
        entry.addr.sin_addr.s_addr = htonl(ip_host_order);
        entry.netmask.sin_family = AF_INET;
        entry.netmask.sin_addr.s_addr = htonl(netmask_host_order);
        rebuild_links();
    }

    void add_index(std::string ifname, unsigned int ifindex) {
        indices.emplace_back(std::move(ifname), ifindex);
    }
};

FakeIfaddrsState g_fake_ifaddrs;

sniffster::network_interface make_interface() {
    return sniffster::network_interface{"fake0"};
}

extern "C" int getifaddrs(ifaddrs** ifap) {
    *ifap = g_fake_ifaddrs.head;
    return 0;
}

extern "C" void freeifaddrs(ifaddrs* ifa) {
    EXPECT_EQ(ifa, g_fake_ifaddrs.head);
    ++g_fake_ifaddrs.freeifaddrs_calls;
}

extern "C" unsigned int if_nametoindex(const char* ifname) {
    const std::string needle = ifname == nullptr ? "" : ifname;
    for (const auto& [name, ifindex] : g_fake_ifaddrs.indices) {
        if (name == needle) {
            return ifindex;
        }
    }
    return 0;
}

extern "C" int bpf_object__open_skeleton(struct bpf_object_skeleton* s,
                                         const struct bpf_object_open_opts*) {
    ++g_loader.open_skeleton_calls;
    if (s != nullptr && s->map_cnt > 0 && s->prog_cnt > 0) {
        *s->maps[0].map = g_loader.perf_map;
        *s->progs[0].prog = g_loader.program;
    }
    return g_loader.open_skeleton_result;
}

extern "C" int bpf_object__load_skeleton(struct bpf_object_skeleton*) {
    ++g_loader.load_skeleton_calls;
    return g_loader.load_skeleton_result;
}

extern "C" void bpf_object__destroy_skeleton(struct bpf_object_skeleton* s) {
    ++g_loader.destroy_skeleton_calls;
    if (s == nullptr) {
        return;
    }

    std::free(s->maps);
    std::free(s->progs);
    std::free(s);
}

extern "C" int bpf_map__set_max_entries(struct bpf_map* map, __u32 max_entries) {
    ++g_loader.set_max_entries_calls;
    g_loader.last_max_entries = max_entries;
    EXPECT_EQ(map, g_loader.perf_map);
    return g_loader.set_max_entries_result;
}

extern "C" int bpf_map__fd(const struct bpf_map* map) {
    ++g_loader.map_fd_calls;
    EXPECT_EQ(map, g_loader.perf_map);
    return g_loader.map_fd_result;
}

extern "C" int bpf_program__fd(const struct bpf_program* prog) {
    ++g_loader.program_fd_calls;
    EXPECT_EQ(prog, g_loader.program);
    return g_loader.program_fd_result;
}

extern "C" int bpf_xdp_attach(int ifindex, int prog_fd, __u32 flags, const struct bpf_xdp_attach_opts*) {
    ++g_loader.attach_calls;
    g_loader.last_attach_ifindex = ifindex;
    g_loader.last_attach_prog_fd = prog_fd;
    g_loader.last_attach_flags = flags;
    return g_loader.attach_result;
}

extern "C" int bpf_xdp_detach(int ifindex, __u32 flags, const struct bpf_xdp_attach_opts*) {
    ++g_loader.detach_calls;
    g_loader.last_detach_ifindex = ifindex;
    g_loader.last_detach_flags = flags;
    return 0;
}

class XdpCopyModeLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        g_loader = FakeLoaderState{};
        g_fake_ifaddrs = {};
        g_fake_ifaddrs.add_ipv4("fake0", 0xC0A8010A, 0xFFFFFF00);
        g_fake_ifaddrs.add_index("fake0", 7);
    }
};

TEST_F(XdpCopyModeLoaderTest, ConstructorSizesLoadsAndAttaches) {
    {
        sniffster::xdp_copy_mode_loader loader{make_interface()};
        EXPECT_GT(g_loader.last_max_entries, 0u);
        EXPECT_EQ(loader.perf_map_fd(), g_loader.map_fd_result);
    }

    EXPECT_EQ(g_loader.open_skeleton_calls, 1);
    EXPECT_EQ(g_loader.set_max_entries_calls, 1);
    EXPECT_EQ(g_loader.load_skeleton_calls, 1);
    EXPECT_EQ(g_loader.attach_calls, 1);
    EXPECT_EQ(g_loader.program_fd_calls, 1);
    EXPECT_EQ(g_loader.map_fd_calls, 1);
    EXPECT_EQ(g_loader.last_attach_ifindex, 7);
    EXPECT_EQ(g_loader.last_attach_prog_fd, g_loader.program_fd_result);
    EXPECT_EQ(g_loader.detach_calls, 1);
    EXPECT_EQ(g_loader.last_detach_ifindex, 7);
    EXPECT_EQ(g_loader.destroy_skeleton_calls, 1);
}

TEST_F(XdpCopyModeLoaderTest, ThrowsWhenSkeletonOpenFails) {
    g_loader.open_skeleton_result = -7;
    EXPECT_THROW((sniffster::xdp_copy_mode_loader{make_interface()}), std::runtime_error);
    EXPECT_EQ(g_loader.open_skeleton_calls, 1);
    EXPECT_EQ(g_loader.destroy_skeleton_calls, 1);
}

TEST_F(XdpCopyModeLoaderTest, ThrowsWhenPerfMapResizeFails) {
    g_loader.set_max_entries_result = -9;
    EXPECT_THROW((sniffster::xdp_copy_mode_loader{make_interface()}), std::runtime_error);
    EXPECT_EQ(g_loader.destroy_skeleton_calls, 1);
}

TEST_F(XdpCopyModeLoaderTest, ThrowsWhenKernelLoadFails) {
    g_loader.load_skeleton_result = -7;
    EXPECT_THROW((sniffster::xdp_copy_mode_loader{make_interface()}), std::runtime_error);
    EXPECT_EQ(g_loader.destroy_skeleton_calls, 1);
}

TEST_F(XdpCopyModeLoaderTest, ThrowsWhenNicAttachFailsAndStillDestroysSkeleton) {
    g_loader.attach_result = -5;
    EXPECT_THROW((sniffster::xdp_copy_mode_loader{make_interface()}), std::runtime_error);
    EXPECT_EQ(g_loader.attach_calls, 1);
    EXPECT_EQ(g_loader.detach_calls, 0);
    EXPECT_EQ(g_loader.destroy_skeleton_calls, 1);
}

} // namespace
