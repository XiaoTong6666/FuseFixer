/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <type_traits>

namespace fusehide {

// Hook backends exchange untyped addresses. Keep that platform-specific conversion here so callers
// retain the exact original function signature.
template <typename Function>
class HookOriginal final {
    static_assert(std::is_pointer_v<Function>);
    static_assert(std::is_function_v<std::remove_pointer_t<Function>>);
    static_assert(sizeof(Function) == sizeof(void*));

   public:
    Function get() const noexcept {
        return reinterpret_cast<Function>(address_);
    }

    void*& rawStorage() noexcept {
        return address_;
    }

   private:
    void* address_ = nullptr;
};

}  // namespace fusehide
