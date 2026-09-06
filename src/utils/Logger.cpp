// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../../include/utils/Logger.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        // Static member initialization
        std::unique_ptr<Logger> Logger::m_instance = nullptr;
        std::once_flag Logger::m_onceFlag;

        Logger& Logger::Get()
        {
            std::call_once(m_onceFlag, []() {
                m_instance.reset(new Logger());
            });
            return *m_instance;
        }

        Logger::Logger()
            : m_minLevel(LogLevel::Info)
            , m_consoleEnabled(true)
            , m_fileEnabled(false)
        {
            // Default constructor
        }

        Logger::~Logger()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_fileStream.is_open())
                m_fileStream.close();
        }

        void Logger::SetLogLevel(LogLevel level)
        {
            m_minLevel.store(level);
        }

        void Logger::SetConsoleOutput(bool enabled)
        {
            m_consoleEnabled.store(enabled);
        }

        void Logger::SetLogFile(const std::string& filePath, bool append)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_fileStream.is_open())
                m_fileStream.close();

            if (filePath.empty())
            {
                m_fileEnabled.store(false);
                m_logFilePath.clear();
                return;
            }

            // Open the file
            auto mode = append ? std::ios::app : std::ios::trunc;
            m_fileStream.open(filePath, std::ios::out | mode);
            if (m_fileStream.is_open())
            {
                m_fileEnabled.store(true);
                m_logFilePath = filePath;
                Info("Log file opened: " + filePath);
            }
            else
            {
                m_fileEnabled.store(false);
                std::cerr << "[Logger] Failed to open log file: " << filePath << std::endl;
            }
        }

        void Logger::Trace(const std::string& message)
        {
            Log(LogLevel::Trace, message);
        }

        void Logger::Debug(const std::string& message)
        {
            Log(LogLevel::Debug, message);
        }

        void Logger::Info(const std::string& message)
        {
            Log(LogLevel::Info, message);
        }

        void Logger::Warning(const std::string& message)
        {
            Log(LogLevel::Warning, message);
        }

        void Logger::Error(const std::string& message)
        {
            Log(LogLevel::Error, message);
        }

        void Logger::Critical(const std::string& message)
        {
            Log(LogLevel::Critical, message);
        }

        void Logger::Log(LogLevel level, const std::string& message)
        {
            // Check if this level should be logged
            if (level < m_minLevel.load())
                return;

            std::string levelStr = LevelToString(level);
            WriteLog(levelStr, message);
        }

        std::string Logger::LevelToString(LogLevel level) const
        {
            switch (level)
            {
                case LogLevel::Trace:    return "TRACE";
                case LogLevel::Debug:    return "DEBUG";
                case LogLevel::Info:     return "INFO";
                case LogLevel::Warning:  return "WARN";
                case LogLevel::Error:    return "ERROR";
                case LogLevel::Critical: return "CRITICAL";
                case LogLevel::None:     return "NONE";
                default:                 return "UNKNOWN";
            }
        }

        void Logger::WriteLog(const std::string& levelStr, const std::string& message)
        {
            std::string timestamp = GetTimestamp();
            std::string threadId = std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));

            // Format: [2026-09-06 12:34:56.789] [INFO] [T12345] message
            std::ostringstream formatted;
            formatted << timestamp << " [" << levelStr << "] [T" << threadId << "] " << message;

            std::string output = formatted.str();

            // Lock for thread safety (both console and file)
            std::lock_guard<std::mutex> lock(m_mutex);

            // Console output
            if (m_consoleEnabled.load())
            {
                if (levelStr == "ERROR" || levelStr == "CRITICAL")
                    std::cerr << output << std::endl;
                else
                    std::cout << output << std::endl;
            }

            // File output
            if (m_fileEnabled.load() && m_fileStream.is_open())
            {
                m_fileStream << output << std::endl;
                m_fileStream.flush();  // Ensure it's written immediately
            }
        }

        std::string Logger::GetTimestamp() const
        {
            auto now = std::chrono::system_clock::now();
            auto now_time_t = std::chrono::system_clock::to_time_t(now);
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            std::tm now_tm;
#ifdef _WIN32
            localtime_s(&now_tm, &now_time_t);
#else
            localtime_r(&now_time_t, &now_tm);
#endif

            std::ostringstream oss;
            oss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << now_ms.count();
            return oss.str();
        }

    } // namespace Utils
} // namespace SecureKeyRetriever
