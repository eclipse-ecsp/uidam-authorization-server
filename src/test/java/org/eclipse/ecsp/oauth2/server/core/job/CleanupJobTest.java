/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.job;

import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.CleanupJobAuditRepository;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Token cleanup job Test.
 *
 */

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class CleanupJobTest {

    private static final int VERIFY_COUNT_ONE = 1;
    private static final int BATCH_SIZE = 100;
    private static final int EXPIRES_BEFORE_DAYS = 7;

    @Mock
    AuthorizationRepository authorizationRepository;

    @Mock
    CleanupJobAuditRepository cleanupJobAuditRepository;

    @Mock
    TenantConfigurationService tenantConfigurationService;

    private CleanupJob cleanupJob;

    @BeforeEach
    void setup() {
        cleanupJob = new CleanupJob(authorizationRepository,
            cleanupJobAuditRepository, tenantConfigurationService);
        ReflectionTestUtils.setField(cleanupJob, "batchSize", BATCH_SIZE);
        ReflectionTestUtils.setField(cleanupJob, "expiresBeforeInDays", EXPIRES_BEFORE_DAYS);
    }

    @Test
    void testTokenCleanupJob() {
        Set<String> tenants = new HashSet<>();
        tenants.add("ecsp");
        when(tenantConfigurationService.getAllTenants()).thenReturn(tenants);
        when(authorizationRepository.count()).thenReturn(1L);
        when(authorizationRepository.countByTokenOrCodeExpiresBefore(any(Instant.class)))
            .thenReturn(1L);
        List<String> ids = List.of("token-id-1");
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt()))
            .thenReturn(ids)
            .thenReturn(Collections.emptyList());
        when(cleanupJobAuditRepository.save(any()))
            .thenReturn(new org.eclipse.ecsp.oauth2.server.core.entities.CleanupJobAudit());
        
        // Test should complete without throwing exception
        cleanupJob.executeCleanupTasks();
        
        // Verify the cleanup task was invoked
        verify(tenantConfigurationService, times(VERIFY_COUNT_ONE)).getAllTenants();
        verify(authorizationRepository, times(VERIFY_COUNT_ONE)).count();
    }

    @Test
    void testTokenCleanupJobNoTokens() {
        Set<String> tenants = new HashSet<>();
        tenants.add("ecsp");
        when(tenantConfigurationService.getAllTenants()).thenReturn(tenants);
        when(authorizationRepository.count()).thenReturn(0L);
        when(authorizationRepository.countByTokenOrCodeExpiresBefore(any(Instant.class)))
            .thenReturn(0L);
        List<String> ids = Collections.emptyList();
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt()))
            .thenReturn(ids);
        when(cleanupJobAuditRepository.save(any()))
            .thenReturn(new org.eclipse.ecsp.oauth2.server.core.entities.CleanupJobAudit());
        
        // Test should complete without throwing exception
        cleanupJob.executeCleanupTasks();
        
        // Verify the cleanup task was invoked
        verify(tenantConfigurationService, times(VERIFY_COUNT_ONE)).getAllTenants();
    }

    @Test
    void testTokenCleanupJobExceptionCase() {
        Set<String> tenants = new HashSet<>();
        tenants.add("ecsp");
        when(tenantConfigurationService.getAllTenants()).thenReturn(tenants);
        when(authorizationRepository.count()).thenReturn(1L);
        when(authorizationRepository.countByTokenOrCodeExpiresBefore(any(Instant.class)))
            .thenReturn(1L);
        when(authorizationRepository.findByTokenOrCodeExpiresBefore(any(Instant.class), anyInt()))
            .thenThrow(new RuntimeException("Database error"));
        when(cleanupJobAuditRepository.save(any()))
            .thenReturn(new org.eclipse.ecsp.oauth2.server.core.entities.CleanupJobAudit());
        
        // Exception should be caught and handled internally, no exception thrown
        cleanupJob.executeCleanupTasks();
        
        // Verify the cleanup task was attempted
        verify(tenantConfigurationService, times(VERIFY_COUNT_ONE)).getAllTenants();
    }

}
