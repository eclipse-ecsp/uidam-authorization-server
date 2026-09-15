/********************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.metrics;

/**
 * Enum defining all supported metric types for authentication and authorization tracking.
 * Each enum constant contains the metric name and its corresponding description template.
 *
 * <p>This enum provides type safety and centralized management of metric definitions,
 * replacing the previous Map-based approach for better maintainability and compile-time validation.
 *
 * @author khkumar
 * @since 1.0
 */
public enum MetricType {

    /**
     * Tracks total login attempts per tenant.
     */
    TOTAL_LOGIN_ATTEMPTS("total.login.attempts", "Total number of login attempts"),
    
    /**
     * Tracks successful login attempts per tenant.
     */
    SUCCESS_LOGIN_ATTEMPTS("success.login.attempts",
                "Total number of successful login attempts"),

    /**
     * Tracks successful login attempts using internal credentials per tenant.
     */
    SUCCESS_LOGIN_BY_INTERNAL_CREDENTIALS("success.login.attempts.by.internal.credentials",
                                           "Total number of successful login attempts using internal credentials"),

    /**
     * Tracks successful login attempts using external IDP credentials per tenant.
     */
    SUCCESS_LOGIN_BY_EXTERNAL_IDP_CREDENTIALS("success.login.attempts.by.external.idp.credentials",
            "Total number of successful login attempts using external IDP credentials"),

    /**
     * Tracks failed login attempts per tenant.
     */
    FAILURE_LOGIN_ATTEMPTS("failure.login.attempts",
                "Total number of failed login attempts"),

    /**
     * Tracks failed login attempts due to captcha failure per tenant.
     */
    FAILURE_LOGIN_CAPTCHA("failure.login.attempts.captcha",
                          "Total number of failed login attempts due to captcha failure"),

    /**
     * Tracks failed login attempts due to wrong password per tenant.
     */
    FAILURE_LOGIN_WRONG_PASSWORD("failure.login.attempts.wrong.password",
                                  "Total number of failed login attempts due to wrong password"),

    /**
     * Tracks failed login attempts due to user not found per tenant.
     */
    FAILURE_LOGIN_USER_NOT_FOUND("failure.login.attempts.user.not.found",
                                  "Total number of failed login attempts due to user not found"),

    /**
     * Tracks failed login attempts due to account not found per tenant.
     */
    FAILURE_LOGIN_ACCOUNT_NOT_FOUND("failure.login.attempts.account.not.found",
                                     "Total number of failed login attempts due to account not found"),

    /**
     * Tracks failed login attempts due to user being blocked per tenant.
     */
    FAILURE_LOGIN_USER_BLOCKED("failure.login.attempts.user.blocked",
                                "Total number of failed login attempts due to user being blocked"),

    /**
     * Tracks failed login attempts due to account being locked per tenant.
     */
    FAILURE_LOGIN_ACCOUNT_LOCKED("failure.login.attempts.account.locked",
                                  "Total number of failed login attempts due to account being locked"),

    // ========== MFA Metrics ==========

    /**
     * Tracks first-time MFA enrollment initiations (unenrolled user intercepted by MFA filter).
     */
    MFA_ENROLLMENT_INITIATED("mfa.enrollment.initiated",
                              "Total number of first-time MFA enrollment initiations"),

    /**
     * Tracks successful MFA enrollments (TOTP verified and enrollment activated).
     */
    MFA_ENROLLMENT_SUCCESS("mfa.enrollment.success",
                            "Total number of successful MFA enrollments"),

    /**
     * Tracks failed TOTP verifications during enrollment.
     */
    MFA_ENROLLMENT_FAILURE("mfa.enrollment.failure",
                            "Total number of failed TOTP verifications during enrollment"),

    /**
     * Tracks successful MFA challenge completions during login.
     */
    MFA_CHALLENGE_SUCCESS("mfa.challenge.success",
                           "Total number of successful MFA challenge completions"),

    /**
     * Tracks failed MFA challenge attempts during login.
     */
    MFA_CHALLENGE_FAILURE("mfa.challenge.failure",
                           "Total number of failed MFA challenge attempts"),

    /**
     * Tracks successful MFA account recoveries via recovery key.
     */
    MFA_RECOVERY_SUCCESS("mfa.recovery.success",
                          "Total number of successful MFA account recoveries via recovery key"),

    /**
     * Tracks backup codes consumed during account recovery.
     */
    MFA_BACKUP_CODE_USED("mfa.backup.code.used",
                          "Total number of backup codes consumed during account recovery");

    private final String metricName;
    private final String description;

    /**
     * Constructs a MetricType enum constant.
     *
     * @param metricName the unique identifier for this metric type
     * @param description the description for this metric type
     */
    MetricType(String metricName, String description) {
        this.metricName = metricName;
        this.description = description;
    }

    /**
     * Gets the metric name/identifier.
     *
     * @return the metric name
     */
    public String getMetricName() {
        return metricName;
    }

    /**
     * Gets the description for this metric type.
     *
     * @return the description for this metric type
     */
    public String getDescription() {
        return description;
    }

    /**
     * Finds a MetricType by its metric name.
     *
     * @param metricName the metric name to search for
     * @return the matching MetricType, or null if not found
     */
    public static MetricType fromMetricName(String metricName) {
        if (metricName == null) {
            return null;
        }

        for (MetricType type : MetricType.values()) {
            if (type.metricName.equals(metricName)) {
                return type;
            }
        }
        return null;
    }

}
