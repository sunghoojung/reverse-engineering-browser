// Copyright (c) 2026 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

#ifndef BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_LOCAL_IPC_CLIENT_H_
#define BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_LOCAL_IPC_CLIENT_H_

#include <cstdint>
#include <string>

#include "base/files/file_path.h"

namespace reb {

// Connects to a user-owned local receiver and authenticates the session before
// returning the descriptor. The token file must be a user-owned regular file
// with mode 0600. Returns -1 without leaving a connected descriptor on error.
[[nodiscard]] int ConnectNativeLocalIpc(const std::string& socket_path,
                                        const base::FilePath& token_path,
                                        std::uint64_t session_id,
                                        bool non_blocking);

}  // namespace reb

#endif  // BRAVE_COMPONENTS_REVERSE_ENGINEERING_BROWSER_BROWSER_NATIVE_LOCAL_IPC_CLIENT_H_
