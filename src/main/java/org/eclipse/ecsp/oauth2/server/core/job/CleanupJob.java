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

import org.eclipse.ecsp.oauth2.server.core.entities.CleanupJobAudit;
import org.eclipse.ecsp.oauth2.server.core.exception.CleanupJobException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.CleanupJobAuditRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.AUTHORIZATION_TABLE;

/**
 * This class is used to schedule token cleanup job.
 * 
 *
 */
@Component
public class CleanupJob {
    @Autowired
    AuthorizationRepository authorizationRepository;
    @Autowired
    CleanupJobAuditRepository cleanupJobAuditRepository;

    @Value("${cleanup.job.batch.size}")
    private int batchSize;
    @Value("${cleanup.token.expires.before}")
    private int expiresBeforeInDays;

    private static final Logger LOGGER = LoggerFactory.getLogger(CleanupJob.class);

    /**
     * Scheduler for executing cleanup tasks.
     */
    @Scheduled(cron = "${cleanup.job.scheduling.rate.cron}")
    @Retryable(retryFor = CleanupJobException.class, maxAttemptsExpression = "${cleanup.job.scheduling.retry.attempts}",
        backoff = @Backoff(delay = 100))
    public void executeCleanupTasks() {
        LOGGER.info("Clean-up job started!");
        runTokenCleanup();
    }

    /**
     * method for executing cleanup task for tokens.
     */
    private void runTokenCleanup() {
        LOGGER.info("Token clean-up job started with batch size: {}", batchSize);
        Instant currentTime = Instant.now();
        Instant accessTokenExpiresBefore = currentTime.minus(expiresBeforeInDays, ChronoUnit.DAYS);
        LOGGER.info("The time is now {}", currentTime);
        long tokensCount = authorizationRepository.count();
        LOGGER.info("Total no. of existing tokens: {}", tokensCount);
        long deletedTokenCount = 0;
        CleanupJobAudit tokenCleanupAuditEntity = new CleanupJobAudit();
        try {
            long tokensEligibleForDeletion = authorizationRepository
                    .countByTokenOrCodeExpiresBefore(accessTokenExpiresBefore);
            LOGGER.info("Total no. of tokens eligible for deletion: {}", tokensEligibleForDeletion);
            tokenCleanupAuditEntity.setCleanupJobStartedAt(accessTokenExpiresBefore);
            tokenCleanupAuditEntity.setTotalExistingRecords(tokensCount);
            tokenCleanupAuditEntity.setRecordsTableName(AUTHORIZATION_TABLE);

            while (true) {
                List<String> ids = authorizationRepository.findByTokenOrCodeExpiresBefore(accessTokenExpiresBefore,
                        batchSize);
                if (ids.isEmpty()) {
                    break;
                }
                LOGGER.info("total entities to be deleted in current batch: {}", ids.size());
                authorizationRepository.deleteAllById(ids);
                deletedTokenCount = deletedTokenCount + ids.size();
            }
            tokenCleanupAuditEntity.setTotalDeletedRecords(deletedTokenCount);
            tokenCleanupAuditEntity.setCleanupJobCompletedAt(Instant.now());
            tokenCleanupAuditEntity.setJobCompleted(true);
            cleanupJobAuditRepository.save(tokenCleanupAuditEntity);
            LOGGER.info("Deleted {} expired tokens", deletedTokenCount);
            LOGGER.info("Job completed in {} seconds",
                    Duration.between(currentTime, Instant.now()).getSeconds());
        } catch (Exception ex) {
            LOGGER.error("exception occurred while performing token cleanup.");
            tokenCleanupAuditEntity.setTotalDeletedRecords(deletedTokenCount);
            cleanupJobAuditRepository.save(tokenCleanupAuditEntity);
            LOGGER.error("cleanup job status: {}", tokenCleanupAuditEntity.isJobCompleted());
            throw new CleanupJobException("exception occurred while performing token cleanup: ", ex);
        }
    }
}
