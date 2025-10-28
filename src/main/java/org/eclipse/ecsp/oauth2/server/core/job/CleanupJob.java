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

import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.entities.CleanupJobAudit;
import org.eclipse.ecsp.oauth2.server.core.exception.CleanupJobException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.CleanupJobAuditRepository;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.AUTHORIZATION_TABLE;

/**
 * This class is used to schedule token cleanup job per tenant.
 * The cleanup job runs for all configured tenants to ensure expired tokens
 * are cleaned up across the entire multi-tenant system.
 */
@Component
public class CleanupJob {
    
    private final AuthorizationRepository authorizationRepository;
    private final CleanupJobAuditRepository cleanupJobAuditRepository;
    private final TenantConfigurationService tenantConfigurationService;

    @Value("${cleanup.job.batch.size}")
    private int batchSize;
    
    @Value("${cleanup.token.expires.before}")
    private int expiresBeforeInDays;

    private static final Logger LOGGER = LoggerFactory.getLogger(CleanupJob.class);

    /**
     * Constructor for dependency injection.
     *
     * @param authorizationRepository the authorization repository
     * @param cleanupJobAuditRepository the cleanup job audit repository
     * @param tenantConfigurationService the tenant configuration service
     */
    public CleanupJob(AuthorizationRepository authorizationRepository,
                     CleanupJobAuditRepository cleanupJobAuditRepository,
                     TenantConfigurationService tenantConfigurationService) {
        this.authorizationRepository = authorizationRepository;
        this.cleanupJobAuditRepository = cleanupJobAuditRepository;
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Scheduler for executing cleanup tasks.
     */
    @Scheduled(cron = "${cleanup.job.scheduling.rate.cron}")
    @Retryable(retryFor = CleanupJobException.class, maxAttemptsExpression = "${cleanup.job.scheduling.retry.attempts}",
        backoff = @Backoff(delay = 100))
    public void executeCleanupTasks() {
        LOGGER.info("Clean-up job started for all tenants!");
        try {
            Set<String> tenantIds = tenantConfigurationService.getAllTenants();
            if (tenantIds == null || tenantIds.isEmpty()) {
                LOGGER.warn("No tenants configured for cleanup job");
                return;
            }
            
            LOGGER.info("Starting cleanup for {} tenant(s)", tenantIds.size());
            for (String tenantId : tenantIds) {
                try {
                    // Set tenant context for this cleanup task
                    TenantContext.setCurrentTenant(tenantId);
                    LOGGER.info("Processing cleanup for tenant: {}", tenantId);
                    runTokenCleanupForTenant(tenantId);
                } catch (Exception ex) {
                    LOGGER.error("Failed to cleanup tokens for tenant: {}", tenantId, ex);
                    // Continue with next tenant instead of throwing exception
                } finally {
                    // Clear tenant context after processing this tenant
                    TenantContext.clear();
                }
            }
            LOGGER.info("Clean-up job completed for all tenants!");
        } catch (Exception ex) {
            LOGGER.error("Exception occurred while fetching tenant list for cleanup", ex);
            throw new CleanupJobException("Failed to execute cleanup tasks for tenants", ex);
        }
    }

    /**
     * Method for executing cleanup task for tokens per tenant.
     *
     * @param tenantId the tenant ID for which cleanup should be performed
     */
    private void runTokenCleanupForTenant(String tenantId) {
        LOGGER.info("Token clean-up job started for tenant: {} with batch size: {}", tenantId, batchSize);
        Instant currentTime = Instant.now();
        Instant accessTokenExpiresBefore = currentTime.minus(expiresBeforeInDays, ChronoUnit.DAYS);
        LOGGER.info("Cleanup time threshold for tenant {}: {}", tenantId, currentTime);
        long tokensCount = authorizationRepository.count();
        LOGGER.info("Total no. of existing tokens for tenant {}: {}", tenantId, tokensCount);
        long deletedTokenCount = 0;
        CleanupJobAudit tokenCleanupAuditEntity = new CleanupJobAudit();
        try {
            long tokensEligibleForDeletion = authorizationRepository
                .countByTokenOrCodeExpiresBefore(accessTokenExpiresBefore);
            LOGGER.info("Total no. of tokens eligible for deletion in tenant {}: {}",
                tenantId, tokensEligibleForDeletion);
            tokenCleanupAuditEntity.setCleanupJobStartedAt(accessTokenExpiresBefore);
            tokenCleanupAuditEntity.setTotalExistingRecords(tokensCount);
            tokenCleanupAuditEntity.setRecordsTableName(AUTHORIZATION_TABLE);

            while (true) {
                List<String> ids = authorizationRepository.findByTokenOrCodeExpiresBefore(accessTokenExpiresBefore,
                        batchSize);
                if (ids.isEmpty()) {
                    break;
                }
                LOGGER.info("Total entities to be deleted in current batch for tenant {}: {}", tenantId, ids.size());
                authorizationRepository.deleteAllById(ids);
                deletedTokenCount = deletedTokenCount + ids.size();
            }
            tokenCleanupAuditEntity.setTotalDeletedRecords(deletedTokenCount);
            tokenCleanupAuditEntity.setCleanupJobCompletedAt(Instant.now());
            tokenCleanupAuditEntity.setJobCompleted(true);
            cleanupJobAuditRepository.save(tokenCleanupAuditEntity);
            LOGGER.info("Deleted {} expired tokens for tenant {}", deletedTokenCount, tenantId);
            LOGGER.info("Job completed for tenant {} in {} seconds", tenantId,
                    Duration.between(currentTime, Instant.now()).getSeconds());
        } catch (Exception ex) {
            LOGGER.error("Exception occurred while performing token cleanup for tenant: {}", tenantId, ex);
            tokenCleanupAuditEntity.setTotalDeletedRecords(deletedTokenCount);
            cleanupJobAuditRepository.save(tokenCleanupAuditEntity);
            LOGGER.error("Cleanup job status for tenant {}: {}", tenantId,
                tokenCleanupAuditEntity.isJobCompleted());
            String errorMessage = "Exception occurred while performing token cleanup for tenant: " + tenantId;
            throw new CleanupJobException(errorMessage, ex);
        }
    }
}
