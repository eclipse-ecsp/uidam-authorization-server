/*
 * Copyright (c) 2023 - 2024 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package org.eclipse.ecsp.oauth2.server.core.cache;

import lombok.Data;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Represents the cache details for a client.
 */
@Data
public class ClientCacheDetails {

    private RegisteredClient registeredClient;
    private String additionalInformation;
    private String tenantId;
    private String clientType;
    private String accountType;
    private String accountName;
    private String accountId;
    private boolean cache;

}