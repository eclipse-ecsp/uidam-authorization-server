/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.request.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

/**
 * Request body for uidam-user-management's {@code POST /v1/roles/filter} API.
 */
@Getter
@Setter
public class RolesFilterRequestDto {

    private Set<String> roles;

}
