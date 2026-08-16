#ifndef EBPF_NETWORK_CONTROLS_CONTROL_PLANE_H_
#define EBPF_NETWORK_CONTROLS_CONTROL_PLANE_H_

#include <bpf/libbpf.h>

#include <cstdint>
#include <string>
#include <vector>

class ControlPlane {
 public:
  ControlPlane();

  int init(int ifindex);
  void block_cidr(const std::string& cidr);
  std::vector<std::string> detect_attacks();
  void shutdown();

 private:
  struct bpf_object* bpf_obj_ = nullptr;
  struct bpf_map* cidr_map_ = nullptr;
  struct bpf_map* syn_map_ = nullptr;
  bool bpf_ok_;
  int xdp_ifindex_;
  std::uint64_t syn_threshold_;
};

#endif  // EBPF_NETWORK_CONTROLS_CONTROL_PLANE_H_
