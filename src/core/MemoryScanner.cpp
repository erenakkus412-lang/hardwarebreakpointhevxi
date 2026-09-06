// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/core/MemoryScanner.hpp"
#include "../../include/utils/Logger.hpp"
#include <cmath>
#include <algorithm>
#include <array>

namespace SecureKeyRetriever
{
    namespace Core
    {
        HANDLE MemoryScanner::OpenProcessForReading(DWORD pid)
        {
            HANDLE hProcess = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                FALSE,
                pid
            );

            if (!hProcess)
            {
                Utils::Logger::Get().LogWarning("Failed to open process PID " + std::to_string(pid) +
                                                " (Error: " + std::to_string(GetLastError()) + ")");
            }

            return hProcess;
        }

        bool MemoryScanner::IsRegionSuitable(const MEMORY_BASIC_INFORMATION& mbi)
        {
            // Must be committed, readable, and not reserved
            if (mbi.State != MEM_COMMIT)
                return false;

            // Must be readable (PAGE_READWRITE, PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
            if (!(mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                return false;

            // Skip extremely small regions (less than 4 KB)
            if (mbi.RegionSize < 4096)
                return false;

            // Skip regions that are too large (avoid excessive scanning)
            if (mbi.RegionSize > 100 * 1024 * 1024) // 100 MB limit
                return false;

            return true;
        }

        bool MemoryScanner::ScanProcessMemory(
            DWORD pid,
            std::function<bool(uintptr_t address, const uint8_t* data, size_t size)> patternCallback,
            size_t maxRegionSize)
        {
            if (!patternCallback)
            {
                Utils::Logger::Get().LogError("ScanProcessMemory: patternCallback is null");
                return false;
            }

            HANDLE hProcess = OpenProcessForReading(pid);
            if (!hProcess)
                return false;

            bool result = false;
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);

            uintptr_t currentAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
            uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

            MEMORY_BASIC_INFORMATION mbi = {};
            std::vector<uint8_t> buffer;

            Utils::Logger::Get().LogInfo("Scanning process memory: PID " + std::to_string(pid) +
                                         " from 0x" + Utils::StringUtils::ToHex(currentAddress) +
                                         " to 0x" + Utils::StringUtils::ToHex(maxAddress));

            while (currentAddress < maxAddress)
            {
                SIZE_T resultSize = VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddress),
                                                   &mbi, sizeof(mbi));

                if (resultSize == 0)
                {
                    // Move to next region
                    currentAddress += 0x1000;
                    continue;
                }

                if (IsRegionSuitable(mbi))
                {
                    // Limit region size to avoid reading huge blocks
                    size_t regionToRead = static_cast<size_t>(mbi.RegionSize);
                    if (regionToRead > maxRegionSize)
                        regionToRead = maxRegionSize;

                    buffer.resize(regionToRead);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionToRead, &bytesRead))
                    {
                        // Call the callback with the region data
                        bool shouldContinue = patternCallback(
                            reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                            buffer.data(),
                            bytesRead
                        );

                        if (!shouldContinue)
                        {
                            result = true;
                            Utils::Logger::Get().LogInfo("Scan stopped by callback at 0x" +
                                                         Utils::StringUtils::ToHex(reinterpret_cast<uintptr_t>(mbi.BaseAddress)));
                            break;
                        }
                    }
                }

                // Move to next region
                currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            CloseHandle(hProcess);
            Utils::Logger::Get().LogInfo("Process memory scan completed for PID " + std::to_string(pid));
            return true;
        }

        std::vector<uint8_t> MemoryScanner::ReadProcessMemory(
            HANDLE hProcess,
            uintptr_t address,
            size_t size)
        {
            if (!hProcess || size == 0)
                return {};

            std::vector<uint8_t> buffer(size);
            SIZE_T bytesRead = 0;

            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                                   buffer.data(), size, &bytesRead))
            {
                Utils::Logger::Get().LogWarning("ReadProcessMemory failed at 0x" +
                                                Utils::StringUtils::ToHex(address) +
                                                " (Error: " + std::to_string(GetLastError()) + ")");
                return {};
            }

            buffer.resize(bytesRead);
            return buffer;
        }

        double MemoryScanner::CalculateEntropy(const uint8_t* data, size_t len)
        {
            if (!data || len == 0)
                return 0.0;

            std::array<size_t, 256> counts = {};
            for (size_t i = 0; i < len; ++i)
            {
                counts[data[i]]++;
            }

            double entropy = 0.0;
            for (size_t i = 0; i < 256; ++i)
            {
                if (counts[i] > 0)
                {
                    double p = static_cast<double>(counts[i]) / len;
                    entropy -= p * std::log2(p);
                }
            }
            return entropy;
        }

        bool MemoryScanner::LooksLikeKey(const uint8_t* data, size_t len)
        {
            if (!data || len < 32)
                return false;

            // Check for key-like characteristics (AES-256 key = 32 bytes)
            // 1. High entropy (randomness)
            double entropy = CalculateEntropy(data, 32);
            if (entropy < 6.5) // Random data should have entropy close to 8.0
                return false;

            // 2. Not all zeros or all FFs
            int zeros = 0, ffs = 0;
            for (size_t i = 0; i < 32; ++i)
            {
                if (data[i] == 0x00) zeros++;
                if (data[i] == 0xFF) ffs++;
            }
            if (zeros > 4 || ffs > 4)
                return false;

            // 3. Byte distribution shouldn't be too uniform (e.g., alternating pattern)
            int unique = 0;
            bool seen[256] = {false};
            for (size_t i = 0; i < 32; ++i)
            {
                if (!seen[data[i]])
                {
                    seen[data[i]] = true;
                    unique++;
                }
            }
            if (unique < 16) // Too few unique bytes suggests non-random data
                return false;

            return true;
        }

    } // namespace Core
} // namespace SecureKeyRetriever
