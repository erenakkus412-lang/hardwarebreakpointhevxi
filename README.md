# Windows Process Debugging & Hardware Breakpoint Research Framework

**A Deep Dive into Windows Internals: Indirect Syscalls and Hardware Breakpoints.**

This repository serves as a comprehensive educational framework for understanding how advanced Windows process debugging techniques work, specifically targeting defensive and blue-team researchers. This project demonstrates how to monitor processes, enumerate memory regions, and utilize hardware debug registers (DR0/DR7) using modern, stealthier syscall implementations.

## 🧠 Overview
Modern Endpoint Detection and Response (EDR) solutions and advanced threats rely on low-level Windows APIs to monitor and control system behavior. This framework provides a practical, clean, and educational example of how these internals operate, allowing researchers to better understand how to detect or defend against these techniques.

## 🛠️ Key Features
- **Indirect Syscall Implementation (NullGate):** Demonstrates a modern, stealthy approach to calling Native API functions (`NtGetContextThread`, `NtSetContextThread`, etc.) without relying on user-mode hooks, showcasing how advanced malware and EDRs operate under the hood.
- **Hardware Breakpoints (DR0/DR7):** Shows how to enumerate all threads of a process (`NtGetNextThread`), suspend them, and set/clear hardware breakpoints directly in the CPU debug registers. This bypasses traditional software breakpoints (e.g., 0xCC).
- **Process Memory Enumeration:** Provides utilities to map out the virtual memory regions of a target process using `VirtualQueryEx`.
- **SeDebugPrivilege:** Demonstrates the proper way to acquire the powerful debugging privilege required for low-level operations.

## 🎯 Purpose & Disclaimer
**This project is strictly for educational and defensive purposes.** 
The goal is to aid Blue Teamers, SOC analysts, and malware researchers in understanding the low-level mechanics of process manipulation, so they can better detect, analyze, and defend against sophisticated threats. All examples are run against safe, local test processes (e.g., Notepad).

## 👨‍💻 Author
Developed by **Eren Taha Akkuş**, a dedicated and passionate **Turkish Cybersecurity Researcher**, focused on Windows internals and offensive/defensive security research.

## 🚀 Getting Started
> **Requirements:** Windows 10/11 (x64), Administrator privileges.

1. Clone the repository.
2. Compile with x64 architecture (e.g., using MSVC or MinGW-w64).
3. Run as Administrator to grant SeDebugPrivilege for process debugging.
4. Observe the console output as the framework analyzes a test process and configures hardware breakpoints.
