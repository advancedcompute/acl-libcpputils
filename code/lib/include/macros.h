
/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <string>
#if defined(__linux__)
#include <cstring>
#endif

#if defined(_MSC_VER) || defined(_WIN64) || defined(_WIN32)
#define __PRETTY_FUNCTION__     __FUNCTION__
#endif

namespace cpp {
    namespace utils {

        inline std::string methodName(const std::string& prettyFunction)
        {
            size_t end = prettyFunction.rfind("(");
            size_t begin = prettyFunction.rfind("::", end) + sizeof("::") - 1;
            return prettyFunction.substr(begin, end - begin);
        }

        inline std::string className(const std::string& prettyFunction)
        {
            size_t end = prettyFunction.rfind("(");
            std::string sub = prettyFunction.substr(0, end);
            end = sub.find_last_of("::") - 1;
            sub = sub.substr(0, end);
            size_t begin = sub.find_last_of("::") + 1;
            return sub.substr(begin, end).c_str();
        }
    }
}

#define __METHOD_NAME__         cpp::utils::methodName(__PRETTY_FUNCTION__)
#define __CLASS_NAME__          cpp::utils::className(__PRETTY_FUNCTION__)

#define __METHOD_NAME_CSTR__    __METHOD_NAME__.c_str()
#define __CLASS_NAME_CSTR__     __CLASS_NAME__.c_str()

#define __FILENAME__           (strrchr(__FILE__,'\\')+1)
