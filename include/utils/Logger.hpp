// Copyright (c) 2026 Eren Taha Akkuş
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <memory>
#include <chrono>
#include <sstream>

namespace SecureKeyRetriever
{
    namespace Utils
    {
        /**
         * @brief Log levels for filtering messages.
         */
        enum class LogLevel : uint8_t
        {
            Trace = 0,
            Debug,
            Info,
            Warning,
            Error,
            Critical,
            None  // Disable all logging
        };

        /**
         * @brief Centralized logging system with thread-safe output to console and file.
         * 
         * Singleton pattern. Provides formatted log messages with timestamps,
         * log levels, and optional file output. All methods are thread-safe.
         */
        class Logger
        {
        public:
            /**
             * @brief Get the singleton instance of the Logger.
             * 
             * @return Logger& Reference to the singleton.
             */
            static Logger& Get();

            // Disable copy and move
            Logger(const Logger&) = delete;
            Logger& operator=(const Logger&) = delete;
            Logger(Logger&&) = delete;
            Logger& operator=(Logger&&) = delete;

            /**
             * @brief Sets the minimum log level. Messages below this level are ignored.
             * 
             * @param level The minimum log level.
             */
            void SetLogLevel(LogLevel level);

            /**
             * @brief Enables or disables console output.
             * 
             * @param enabled true to output to console, false to disable.
             */
            void SetConsoleOutput(bool enabled);

            /**
             * @brief Sets the log file path. If empty, file output is disabled.
             * 
             * @param filePath Path to the log file.
             * @param append true to append to existing file, false to overwrite.
             */
            void SetLogFile(const std::string& filePath, bool append = true);

            /**
             * @brief Logs a trace-level message.
             * 
             * @param message The message to log.
             */
            void Trace(const std::string& message);

            /**
             * @brief Logs a debug-level message.
             * 
             * @param message The message to log.
             */
            void Debug(const std::string& message);

            /**
             * @brief Logs an info-level message.
             * 
             * @param message The message to log.
             */
            void Info(const std::string& message);

            /**
             * @brief Logs a warning-level message.
             * 
             * @param message The message to log.
             */
            void Warning(const std::string& message);

            /**
             * @brief Logs an error-level message.
             * 
             * @param message The message to log.
             */
            void Error(const std::string& message);

            /**
             * @brief Logs a critical-level message.
             * 
             * @param message The message to log.
             */
            void Critical(const std::string& message);

            /**
             * @brief Generic log method with explicit level.
             * 
             * @param level The log level.
             * @param message The message to log.
             */
            void Log(LogLevel level, const std::string& message);

        private:
            // Private constructor for singleton
            Logger();
            ~Logger();

            /**
             * @brief Internal method to format and output the log message.
             * 
             * @param level The log level as a string.
             * @param message The message.
             */
            void WriteLog(const std::string& levelStr, const std::string& message);

            /**
             * @brief Formats the current timestamp as a string.
             * 
             * @return std::string Formatted timestamp (YYYY-MM-DD HH:MM:SS.mmm).
             */
            std::string GetTimestamp() const;

            /**
             * @brief Converts a log level to its string representation.
             * 
             * @param level The log level.
             * @return std::string The level name (e.g., "INFO").
             */
            std::string LevelToString(LogLevel level) const;

            // Configuration
            std::atomic<LogLevel> m_minLevel;
            std::atomic<bool> m_consoleEnabled;
            std::atomic<bool> m_fileEnabled;

            // File output
            std::string m_logFilePath;
            std::ofstream m_fileStream;
            mutable std::mutex m_mutex;

            // Singleton instance
            static std::unique_ptr<Logger> m_instance;
            static std::once_flag m_onceFlag;
        };

    } // namespace Utils
} // namespace SecureKeyRetriever
