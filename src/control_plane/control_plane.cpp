#include "control_plane.h"

#include <fstream>
#include <sstream>

ControlPlane::ControlPlane()
    : bpf_ok_(false),
      xdp_ifindex_(0),
      syn_threshold_(200)
{
}

int ControlPlane::init(int ifindex)
{
    xdp_ifindex_ = ifindex;

    if (bpf_obj_ = bpf_object__open_file("src/bpf/xdp_filter.bpf.o", nullptr)) {
        bpf_program__set_type(bpf_object__find_program_by_name(bpf_obj_, "xdp_packet_filter"), BPF_PROG_TYPE_XDP);
        bpf_ok_ = bpf_object__load(bpf_obj_) == 0;
    }

    if (!bpf_ok_)
        return -1;

    cidr_map_ = bpf_object__find_map_by_name(bpf_obj_, "blocked_cidrs");
    syn_map_ = bpf_object__find_map_by_name(bpf_obj_, "syn_counts");

    return bpf_xdp_attach(xdp_ifindex_, bpf_program__fd(bpf_program__next(nullptr, bpf_obj_)), 0, nullptr);
}

void ControlPlane::block_cidr(const std::string& cidr)
{
    if (!bpf_ok_ || !cidr_map_)
        return;

    __u8 value = 1;
    bpf_map__update_elem(cidr_map_, &cidr, sizeof(cidr), &value, sizeof(value), BPF_ANY);
}

std::vector<std::string> ControlPlane::detect_attacks()
{
    std::vector<std::string> events;

    if (!bpf_ok_ || !syn_map_)
        return events;

    __u32 key = 0;
    __u64 value = 0;

    while (bpf_map__get_next_key(syn_map_, &key, &key, nullptr) == 0) {
        if (bpf_map__lookup_elem(syn_map_, &key, sizeof(key), &value, sizeof(value), nullptr) == 0) {
            if (value >= syn_threshold_) {
                events.push_back("syn-flood-candidate:" + std::to_string(key));
                bpf_map__delete_elem(syn_map_, &key, sizeof(key), nullptr);
            }
        }
    }

    return events;
}

void ControlPlane::shutdown()
{
    if (bpf_ok_)
        bpf_xdp_detach(xdp_ifindex_, 0, nullptr);

    if (bpf_obj_)
        bpf_object__close(bpf_obj_);

    bpf_ok_ = false;
}
