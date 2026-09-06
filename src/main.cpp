// ============================================================================
// SecureKeyRetriever - Professional Command-Line Interface
// ============================================================================
// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root.
// ============================================================================
//
// This application retrieves App-Bound Encryption (ABE) keys for Chromium‑based
// browsers (Chrome, Edge, Brave, Vivaldi, Opera, Arc, Avast, etc.) using the
// built‑in COM Elevator interfaces.
//
// Usage examples:
//   SecureKeyRetriever.exe --hex "763230..." --auto-discover
//   SecureKeyRetriever.exe --input "encrypted.bin" --clsid "{...}" --iid "{...}"
//   SecureKeyRetriever.exe --input "encrypted.bin" --known-pairs "pairs.txt" --output "key.bin"
//
// ============================================================================

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <exception>
#include <iomanip>
#include <optional>

#include "SecureKeyRetriever.hpp"  // Main library header
#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"
#include "utils/GuidUtils.hpp"

// ============================================================================
// Helper structures for command‑line parsing
// ============================================================================
struct CliOptions
{
    std::wstring inputFile;          // Input file containing raw encrypted data
    std::string hexData;             // Hex string of encrypted data (alternative to file)
    std::wstring clsidStr;           // CLSID to use directly
    std::wstring iidStr;             // IID to use directly
    std::wstring clsidV2Str;         // Optional second IID (IElevator2)
    std::wstring knownPairsFile;     // File with known CLSID/IID pairs
    bool autoDiscover = false;       // Use AutoDiscover
    bool tryEdge = true;             // Try Edge variants
    bool tryAvast = true;            // Try Avast variants
    int timeoutMs = 30000;           // Timeout for AutoDiscover
    std::wstring outputFile;         // Output file for decrypted data
    bool verbose = false;            // Verbose logging
};

// ============================================================================
// Forward declarations
// ============================================================================
void PrintUsage();
bool ParseArguments(int argc, wchar_t* argv[], CliOptions& options);
bool LoadKnownPairs(const std::wstring& filename, std::vector<std::pair<GUID, GUID>>& knownPairs);
bool LoadDataFromFile(const std::wstring& filename, std::vector<uint8_t>& data);
bool SaveDataToFile(const std::wstring& filename, const std::vector<uint8_t>& data);

// ============================================================================
// Entry point
// ============================================================================
int wmain(int argc, wchar_t* argv[])
{
    // ------------------------------------------------------------------
    // Setup logging
    // ------------------------------------------------------------------
    auto& logger = SecureKeyRetriever::Utils::Logger::Get();
    logger.SetLogLevel(SecureKeyRetriever::Utils::LogLevel::Info);
    logger.SetConsoleOutput(true);
    logger.SetLogFile("securekeyretriever.log", true);   // Append to log file

    logger.Info("==========================================");
    logger.Info(" SecureKeyRetriever v1.0.0 - Starting");
    logger.Info("==========================================");

    // ------------------------------------------------------------------
    // Parse command line
    // ------------------------------------------------------------------
    CliOptions options;
    if (!ParseArguments(argc, argv, options))
    {
        PrintUsage();
        return 1;
    }

    if (options.verbose)
        logger.SetLogLevel(SecureKeyRetriever::Utils::LogLevel::Debug);

    // ------------------------------------------------------------------
    // Load encrypted data
    // ------------------------------------------------------------------
    std::vector<uint8_t> encryptedData;

    if (!options.inputFile.empty())
    {
        logger.Info("Loading encrypted data from file: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.inputFile));
        if (!LoadDataFromFile(options.inputFile, encryptedData))
        {
            logger.Error("Failed to read input file.");
            return 1;
        }
    }
    else if (!options.hexData.empty())
    {
        logger.Info("Parsing encrypted data from hex string...");
        if (!SecureKeyRetriever::Utils::StringUtils::FromHex(options.hexData, encryptedData))
        {
            logger.Error("Invalid hex data provided.");
            return 1;
        }
    }
    else
    {
        logger.Error("No encrypted data provided. Use --hex or --input.");
        PrintUsage();
        return 1;
    }

    logger.Debug("Encrypted data size: " + std::to_string(encryptedData.size()) + " bytes");

    // ------------------------------------------------------------------
    // Main process: decrypt / auto-discover
    // ------------------------------------------------------------------
    try
    {
        // Create the main retriever object
        SecureKeyRetriever::SecureKeyRetriever retriever;

        SecureKeyRetriever::SecureKeyRetriever::DiscoveryResult result;

        if (options.autoDiscover)
        {
            // ------------------------------------------------------------------
            // Auto‑Discovery mode
            // ------------------------------------------------------------------
            logger.Info("Running AutoDiscover with timeout: " + std::to_string(options.timeoutMs) + " ms");

            // Load known pairs if provided
            std::vector<std::pair<GUID, GUID>> knownPairs;
            if (!options.knownPairsFile.empty())
            {
                logger.Info("Loading known CLSID/IID pairs from: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.knownPairsFile));
                if (!LoadKnownPairs(options.knownPairsFile, knownPairs))
                {
                    logger.Warning("Could not load known pairs, continuing with empty list.");
                }
            }
            else
            {
                // Use a small set of well‑known Chrome/Edge pairs as fallback
                // (These are illustrative – real users should provide their own pairs)
                logger.Info("No known pairs file supplied, using built‑in defaults.");
            }

            result = retriever.AutoDiscover(
                encryptedData,
                knownPairs,
                options.tryEdge,
                options.tryAvast,
                options.timeoutMs
            );
        }
        else
        {
            // ------------------------------------------------------------------
            // Direct decryption mode
            // ------------------------------------------------------------------
            if (options.clsidStr.empty() || options.iidStr.empty())
            {
                logger.Error("Direct decryption requires both --clsid and --iid.");
                PrintUsage();
                return 1;
            }

            GUID clsid, iid, iidV2{};
            if (!SecureKeyRetriever::Utils::GuidUtils::StringToGuid(SecureKeyRetriever::Utils::StringUtils::WStringToString(options.clsidStr), clsid))
            {
                logger.Error("Invalid CLSID format: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.clsidStr));
                return 1;
            }
            if (!SecureKeyRetriever::Utils::GuidUtils::StringToGuid(SecureKeyRetriever::Utils::StringUtils::WStringToString(options.iidStr), iid))
            {
                logger.Error("Invalid IID format: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.iidStr));
                return 1;
            }

            std::optional<GUID> optIidV2;
            if (!options.clsidV2Str.empty())
            {
                GUID v2;
                if (!SecureKeyRetriever::Utils::GuidUtils::StringToGuid(SecureKeyRetriever::Utils::StringUtils::WStringToString(options.clsidV2Str), v2))
                {
                    logger.Error("Invalid IID v2 format: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.clsidV2Str));
                    return 1;
                }
                optIidV2 = v2;
            }

            logger.Info("Attempting direct decryption with provided CLSID/IID...");
            auto decrypted = retriever.DecryptKey(encryptedData, clsid, iid, optIidV2, false, false);
            result.success = true;
            result.decryptedData = decrypted;
            result.usedClsid = clsid;
            result.usedIid = iid;
            result.method = "Direct decryption";
        }

        // ------------------------------------------------------------------
        // Process results
        // ------------------------------------------------------------------
        if (result.success)
        {
            logger.Info("Decryption successful!");
            logger.Info("Decrypted data size: " + std::to_string(result.decryptedData.size()) + " bytes");
            logger.Info("Decrypted data (hex): " + SecureKeyRetriever::Utils::StringUtils::ToHex(result.decryptedData, true, ""));

            // Save to output file if requested
            if (!options.outputFile.empty())
            {
                if (SaveDataToFile(options.outputFile, result.decryptedData))
                    logger.Info("Decrypted data saved to: " + SecureKeyRetriever::Utils::StringUtils::WStringToString(options.outputFile));
                else
                    logger.Error("Failed to save output file.");
            }

            // Also print GUIDs used
            if (!SecureKeyRetriever::Utils::GuidUtils::IsGuidEmpty(result.usedClsid))
                logger.Info("Used CLSID: " + SecureKeyRetriever::Utils::GuidUtils::GuidToString(result.usedClsid));
            if (!SecureKeyRetriever::Utils::GuidUtils::IsGuidEmpty(result.usedIid))
                logger.Info("Used IID:   " + SecureKeyRetriever::Utils::GuidUtils::GuidToString(result.usedIid));
            if (!result.method.empty())
                logger.Info("Method:     " + result.method);

            return 0;
        }
        else
        {
            logger.Error("Decryption failed.");
            if (!result.error.empty())
                logger.Error("Reason: " + result.error);
            return 1;
        }
    }
    catch (const std::exception& e)
    {
        logger.Critical(std::string("Unhandled exception: ") + e.what());
        return 1;
    }
    catch (...)
    {
        logger.Critical("Unknown exception occurred.");
        return 1;
    }
}

// ============================================================================
// Function implementations
// ============================================================================
void PrintUsage()
{
    std::wcout << L"\n";
    std::wcout << L"SecureKeyRetriever v1.0.0 - Usage:\n";
    std::wcout << L"=================================\n";
    std::wcout << L"  SecureKeyRetriever [options]\n";
    std::wcout << L"\n";
    std::wcout << L"Options:\n";
    std::wcout << L"  --hex <hex>                Encrypted data as a hex string (v20 format).\n";
    std::wcout << L"  --input <file>             Read encrypted data from a binary file.\n";
    std::wcout << L"  --clsid <guid>             CLSID of the Elevator COM class (direct mode).\n";
    std::wcout << L"  --iid <guid>               IID of the primary interface (direct mode).\n";
    std::wcout << L"  --iid-v2 <guid>            Optional IID for IElevator2 (Chrome 144+).\n";
    std::wcout << L"  --known-pairs <file>       File with known CLSID/IID pairs (line format: CLSID IID).\n";
    std::wcout << L"  --auto-discover            Automatically scan registry for matching CLSIDs.\n";
    std::wcout << L"  --no-edge                  Disable trying Edge variants in AutoDiscover.\n";
    std::wcout << L"  --no-avast                 Disable trying Avast variants in AutoDiscover.\n";
    std::wcout << L"  --timeout <ms>             Timeout for AutoDiscover (default: 30000 ms).\n";
    std::wcout << L"  --output <file>            Save decrypted data to file (raw bytes).\n";
    std::wcout << L"  --verbose                  Enable verbose (debug) logging.\n";
    std::wcout << L"  --help                     Show this help message.\n";
    std::wcout << L"\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  SecureKeyRetriever.exe --hex \"763230123456...\" --auto-discover\n";
    std::wcout << L"  SecureKeyRetriever.exe --input \"encrypted.bin\" --clsid \"{ABCDEF01-...}\" --iid \"{...}\"\n";
    std::wcout << L"  SecureKeyRetriever.exe --input \"encrypted.bin\" --known-pairs \"pairs.txt\" --output \"decrypted.bin\"\n";
    std::wcout << L"\n";
}

bool ParseArguments(int argc, wchar_t* argv[], CliOptions& options)
{
    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];

        if (arg == L"--help" || arg == L"-h" || arg == L"-?")
            return false;   // Will print usage

        else if (arg == L"--hex" || arg == L"-x")
        {
            if (i + 1 >= argc) { std::wcerr << L"--hex requires a value.\n"; return false; }
            options.hexData = SecureKeyRetriever::Utils::StringUtils::WStringToString(argv[++i]);
        }
        else if (arg == L"--input" || arg == L"-i")
        {
            if (i + 1 >= argc) { std::wcerr << L"--input requires a file path.\n"; return false; }
            options.inputFile = argv[++i];
        }
        else if (arg == L"--clsid")
        {
            if (i + 1 >= argc) { std::wcerr << L"--clsid requires a GUID.\n"; return false; }
            options.clsidStr = argv[++i];
        }
        else if (arg == L"--iid")
        {
            if (i + 1 >= argc) { std::wcerr << L"--iid requires a GUID.\n"; return false; }
            options.iidStr = argv[++i];
        }
        else if (arg == L"--iid-v2")
        {
            if (i + 1 >= argc) { std::wcerr << L"--iid-v2 requires a GUID.\n"; return false; }
            options.clsidV2Str = argv[++i];
        }
        else if (arg == L"--known-pairs" || arg == L"-k")
        {
            if (i + 1 >= argc) { std::wcerr << L"--known-pairs requires a file path.\n"; return false; }
            options.knownPairsFile = argv[++i];
        }
        else if (arg == L"--auto-discover" || arg == L"-a")
        {
            options.autoDiscover = true;
        }
        else if (arg == L"--no-edge")
        {
            options.tryEdge = false;
        }
        else if (arg == L"--no-avast")
        {
            options.tryAvast = false;
        }
        else if (arg == L"--timeout")
        {
            if (i + 1 >= argc) { std::wcerr << L"--timeout requires an integer.\n"; return false; }
            options.timeoutMs = _wtoi(argv[++i]);
            if (options.timeoutMs <= 0)
            {
                std::wcerr << L"--timeout must be positive.\n";
                return false;
            }
        }
        else if (arg == L"--output" || arg == L"-o")
        {
            if (i + 1 >= argc) { std::wcerr << L"--output requires a file path.\n"; return false; }
            options.outputFile = argv[++i];
        }
        else if (arg == L"--verbose" || arg == L"-v")
        {
            options.verbose = true;
        }
        else
        {
            std::wcerr << L"Unknown argument: " << arg << L"\n";
            return false;
        }
    }

    // Validate that at least one input method is provided
    if (options.inputFile.empty() && options.hexData.empty())
    {
        std::wcerr << L"Error: No encrypted data provided (use --hex or --input).\n";
        return false;
    }

    // If auto‑discover is false, require explicit CLSID/IID
    if (!options.autoDiscover && (options.clsidStr.empty() || options.iidStr.empty()))
    {
        std::wcerr << L"Error: Direct mode requires --clsid and --iid. Alternatively use --auto-discover.\n";
        return false;
    }

    return true;
}

bool LoadKnownPairs(const std::wstring& filename, std::vector<std::pair<GUID, GUID>>& knownPairs)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Lines may contain comments starting with '#'
        size_t hashPos = line.find('#');
        if (hashPos != std::string::npos)
            line = line.substr(0, hashPos);

        // Trim whitespace
        line = SecureKeyRetriever::Utils::StringUtils::Trim(line);
        if (line.empty())
            continue;

        // Split into two GUIDs (separated by space or tab)
        size_t sep = line.find_first_of(" \t");
        if (sep == std::string::npos)
            continue;

        std::string clsidStr = SecureKeyRetriever::Utils::StringUtils::Trim(line.substr(0, sep));
        std::string iidStr   = SecureKeyRetriever::Utils::StringUtils::Trim(line.substr(sep + 1));

        GUID clsid, iid;
        if (!SecureKeyRetriever::Utils::GuidUtils::StringToGuid(clsidStr, clsid))
            continue;
        if (!SecureKeyRetriever::Utils::GuidUtils::StringToGuid(iidStr, iid))
            continue;

        knownPairs.emplace_back(clsid, iid);
    }

    return !knownPairs.empty();
}

bool LoadDataFromFile(const std::wstring& filename, std::vector<uint8_t>& data)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        return false;
    }

    std::streamsize size = file.tellg();
    if (size <= 0)
        return false;

    file.seekg(0, std::ios::beg);
    data.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(data.data()), size);
    return file.good();
}

bool SaveDataToFile(const std::wstring& filename, const std::vector<uint8_t>& data)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return file.good();
}
