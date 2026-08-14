// Copyright (C) 2026 XiaoTong6666
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <android/log.h>

#include <cstdarg>
#include <cstdio>

inline int FuseHideZygiskLog(int priority, const char* /*tag*/, const char* format, ...) {
    char message[2048];
    constexpr char prefix[] = "[Zygisk] ";
    std::snprintf(message, sizeof(message), "%s", prefix);

    va_list args;
    va_start(args, format);
    std::vsnprintf(message + sizeof(prefix) - 1, sizeof(message) - sizeof(prefix) + 1, format,
                   args);
    va_end(args);
    return __android_log_write(priority, "FuseHide", message);
}

#define __android_log_print FuseHideZygiskLog
