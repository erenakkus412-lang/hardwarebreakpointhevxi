// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <windows.h>
#include <vector>
#include <cstdint>
#include <string>
#include <functional>

namespace SecureKeyRetriever
{
    namespace Core
    {
        /**
         * @brief Memory scanner for reading and analyzing process memory.
         * 
         * This class provides functionality to scan a target process's memory
         * for specific patterns (e.g., cryptographic keys) using efficient
         * region-based scanning with minimal overhead.
         */
        class MemoryScanner
        {
        public:
            /**
             * @brief Default constructor.
             */
            MemoryScanner() = default;

            /**
             * @brief Virtual destructor.
             */
            virtual ~MemoryScanner() = default;

            // Disable copy and move
            MemoryScanner(const MemoryScanner&) = delete;
            MemoryScanner& operator=(const MemoryScanner&) = delete;
            MemoryScanner(MemoryScanner&&) = delete;
            MemoryScanner& operator=(MemoryScanner&&) = delete;

            /**
             * @brief Scans the entire accessible memory of a target process.
             * 
             * @param pid Process ID of the target.
             * @param patternCallback Callback function invoked for each candidate memory region.
             *                         Receives (baseAddress, data, size) as parameters.
             *                         Return true to continue scanning, false to stop.
             * @param maxRegionSize Maximum size of a memory region to scan (default: 4 MB).
             * @return true If scanning completed (or stopped by callback).
             * @return false If failed to open process.
             */
            bool ScanProcessMemory(
                DWORD pid,
                std::function<bool(uintptr_t address, const uint8_t* data, size_t size)> patternCallback,
                size_t maxRegionSize = 4 * 1024 * 1024
            );

            /**
             * @brief Reads a block of memory from a target process.
             * 
             * @param hProcess Handle to the target process (must have PROCESS_VM_READ).
             * @param address Starting address to read from.
             * @param size Number of bytes to read.
             * @return std::vector<uint8_t> The read data, or empty if failed.
             */
            std::vector<uint8_t> ReadProcessMemory(
                HANDLE hProcess,
                uintptr_t address,
                size_t size
            );

            /**
             * @brief Checks if a memory region is likely to contain a cryptographic key.
             * 
             * This is a heuristic function that analyzes entropy, byte distribution,
             * and other characteristics to identify potential AES-256 keys (32 bytes).
             * 
             * @param data Pointer to the data block.
             * @param len Length of the data (must be at least 32).
             * @return true If the data looks like a key.
             * @return false Otherwise.
             */
            static bool LooksLikeKey(const uint8_t* data, size_t len);

            /**
             * @brief Calculates entropy of a data block.
             * 
             * @param data Pointer to data.
             * @param len Length of data.
             * @return double Entropy value (0.0 to 8.0 bits per byte).
             */
            static double CalculateEntropy(const uint8_t* data, size_t len);

        private:
            /**
             * @brief Internal helper to determine if a memory region is worth scanning.
             * 
             * @param mbi Memory region information.
             * @return true If region is suitable for scanning.
             * @return false Otherwise.
             */
            bool IsRegionSuitable(const MEMORY_BASIC_INFORMATION& mbi);

            /**
             * @brief Opens a process with minimal permissions for memory reading.
             * 
             * @param pid Process ID.
             * @return HANDLE Handle to the process, or nullptr if failed.
             */
            HANDLE OpenProcessForReading(DWORD pid);
        };

    } // namespace Core
} // namespace SecureKeyRetriever
