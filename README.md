# eBPF-Based Network Security & Automated Remediation Engine

**Technologies:** C++ · Linux · eBPF · XDP · TC

## Overview

This project focuses on building a **kernel-level network security and automated remediation engine** using eBPF. The system performs early packet processing and filtering inside the Linux networking stack while maintaining a lightweight kernel–user space control plane for attack detection, policy management, and automated response.

## Objectives

* Design a kernel-level packet processing pipeline using **eBPF, XDP, and TC**.
* Perform early packet filtering with minimal user-space overhead.
* Implement **IP/CIDR blocklisting** and domain-based filtering.
* Explore **Layer 7 (L7) traffic inspection**.
* Detect network attacks such as **SYN floods**.
* Automatically enforce security policies and quarantine suspicious traffic.
* Evaluate performance against conventional Linux firewall mechanisms.

## Key Features

### Early Packet Filtering

Uses **XDP (eXpress Data Path)** and **TC (Traffic Control)** to process packets at an early stage of the Linux networking stack, enabling efficient filtering before packets reach higher layers.

### Network Security Policies

The engine supports security mechanisms including:

* IP address blocklisting
* CIDR-based filtering
* Domain filtering
* Suspicious traffic detection
* Traffic quarantine
* Automated rule enforcement

### Kernel–User Space Control Plane

A control plane connects the eBPF programs running in the kernel with user-space components responsible for:

* Event collection
* Attack detection
* Policy updates
* Security decisions
* Automated remediation

Communication and state management are handled using **eBPF maps and asynchronous mechanisms**.

### SYN-Flood Detection

The system monitors network traffic patterns to identify potential **SYN-flood attacks** and automatically applies mitigation policies when suspicious behavior is detected.

## Architecture

```text
                    Network Traffic
                          │
                          ▼
                    ┌───────────┐
                    │    XDP    │
                    │ Early     │
                    │ Filtering │
                    └─────┬─────┘
                          │
                  ┌───────▼───────┐
                  │      TC       │
                  │ Packet Policy │
                  └───────┬───────┘
                          │
              ┌───────────▼───────────┐
              │   eBPF Maps / Events  │
              └───────────┬───────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │  User-Space     │
                 │  Control Plane  │
                 └────────┬────────┘
                          │
              ┌───────────▼───────────┐
              │ Attack Detection &    │
              │ Policy Management     │
              └───────────┬───────────┘
                          │
                          ▼
                 Automated Remediation
```

## Performance Evaluation

The project evaluates the efficiency of the eBPF-based security pipeline using:

* **Throughput**
* **Memory overhead**
* **P99 packet-processing latency**

Performance is compared against conventional **Linux firewall mechanisms** to study the benefits and trade-offs of kernel-level packet processing.

## Tools & Technologies

| Technology    | Purpose                                        |
| ------------- | ---------------------------------------------- |
| **eBPF**      | Kernel-level programmable packet processing    |
| **XDP**       | Early packet processing and filtering          |
| **TC**        | Traffic control and packet policy enforcement  |
| **C++**       | User-space control plane and system components |
| **Linux**     | Target operating system and networking stack   |
| **eBPF Maps** | Kernel–user space state and communication      |

## Learning Outcomes

Through this project, I gained exposure to:

* Linux kernel networking
* eBPF program development
* XDP and TC packet processing
* Kernel–user space communication
* Network attack detection
* Automated security remediation
* High-performance packet filtering
* Network performance benchmarking
* Throughput and P99 latency analysis

## Project Status

**Status:** Academic / Research Project

<!--
## Author

Developed as an academic project under the supervision of **Dr. Rajesh Kumar Pal**.
-->
