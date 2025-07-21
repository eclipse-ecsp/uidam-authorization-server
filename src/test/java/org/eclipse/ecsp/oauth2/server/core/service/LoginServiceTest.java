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

package org.eclipse.ecsp.oauth2.server.core.service;

import io.prometheus.client.CollectorRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.test.TestConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_ATTEMPT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_CAPTCHA_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ENFORCE_AFTER_FAILURE_COUNT;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the LoginService.
 */
@ExtendWith(MockitoExtension.class)
class LoginServiceTest {
    @InjectMocks
    LoginService loginService;

    @Mock
    private TenantProperties tenantProperties;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private HttpServletRequest httpServletRequest;

    /**
     * This method sets up the test environment before each test.
     */
    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(loginService, "request", httpServletRequest);
    }

    /**
     * This method cleans up the test environment after each test.
     * It clears the default registry.
     */
    @BeforeEach
    @AfterEach
    void cleanup() {
        CollectorRegistry.defaultRegistry.clear();
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the login attempt is less than
     * the enforce count.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenLoginAttemptLesserThanEnforceCount() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(1, true, ENFORCE_AFTER_FAILURE_COUNT);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);
        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the login attempt is greater
     * than the enforce count.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenLoginAttemptGreaterThanEnforceCount() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(ENFORCE_AFTER_FAILURE_COUNT, true, 1);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the login attempt equals the
     * enforce count.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenLoginAttemptEqualsEnforceCount() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(1, true, 1);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);
        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the user response captcha is
     * disabled.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenUserResponseCaptchaDisabled() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(1, false, 1);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the tenant properties captcha
     * is disabled.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenTenantPropsCaptchaDisabled() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(false);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the tenant properties captcha is
     * enabled and the failure captcha count is zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenTenantPropsCaptchaEnabledAndFailureCaptchaCountZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures()).thenReturn(0);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the tenant properties captcha is
     * enabled and the failure captcha count is not zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenTenantPropsCaptchaEnabledAndFailureCaptchaCountNotZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(1, true, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures()).thenReturn(1);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the tenant properties captcha
     * is enabled and the login attempt is less than the failure captcha count which is not zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenTenantPropsCaptchaEnabledAndLoginAttemptLesserThanFailureCaptchaCountNotZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(1, true, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the tenant properties captcha is
     * enabled and the login attempt is greater than the failure captcha count which is not zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenTenantPropsCaptchaEnabledAndLoginAttemptGreaterThanFailureCaptchaCountNotZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(TestConstants.LOGIN_ATTEMPT, true, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures()).thenReturn(1);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the tenant properties captcha is
     * enabled and the login attempt equals the failure captcha count which is not zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenTenantPropsCaptchaEnabledAndLoginAttemptEqualsFailureCaptchaCountNotZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(TestConstants.LOGIN_ATTEMPT, true, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the tenant properties captcha
     * is enabled, the failure captcha count is not zero but there is no login attempt.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenTenantPropsCaptchaEnabledAndFailureCaptchaCountNotZeroButNoLoginAttempt() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(null, true, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures()).thenReturn(1);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is enabled for the UI when the tenant properties captcha is
     * enabled and the user response properties are null.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is true.
     */
    @Test
    void isCaptchaEnabledForUiWhenTenantPropsCaptchaEnabledAndUserResponsePropsNull() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures()).thenReturn(0);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertTrue(isCaptchaEnabled);
    }

    /**
     * This test method tests the scenario where the captcha is disabled for the UI when the tenant properties captcha
     * is enabled, the user response properties are null and the tenant failed captcha count is not zero.
     * It sets up the necessary parameters and then calls the isCaptchaEnabledForUserInterface method.
     * The test asserts that the returned value is false.
     */
    @Test
    void isCaptchaDisableForUiWhenTenantPropsCaptchaEnabledAndUserRespPropsNullAndTenantFailedCaptchaCountNotZero() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        setRecaptchaSession(null, null, null);
        Mockito.when(tenantProperties.getUser()).thenReturn(Mockito.mock(UserProperties.class));
        Mockito.when(tenantProperties.getUser().getCaptchaRequired()).thenReturn(true);
        Mockito.when(tenantProperties.getUser().getCaptchaAfterInvalidFailures())
            .thenReturn(ENFORCE_AFTER_FAILURE_COUNT);

        boolean isCaptchaEnabled = loginService.isCaptchaEnabledForUserInterface();
        assertFalse(isCaptchaEnabled);
    }

    /**
     * This method sets up the session for recaptcha testing.
     *
     * @param loginAttempt The number of login attempts made by the user.
     * @param userResponseCaptchaEnabled A flag indicating if the user response captcha is enabled.
     * @param userResponseEnforceAfterNoOfFailures The number of failures after which the captcha should be enforced.
     */
    private void setRecaptchaSession(Integer loginAttempt, Boolean userResponseCaptchaEnabled,
                                     Integer userResponseEnforceAfterNoOfFailures) {
        Mockito.when(httpServletRequest.getSession()).thenReturn(Mockito.mock(HttpSession.class));
        Mockito.when(httpServletRequest.getSession().getAttribute(LOGIN_ATTEMPT)).thenReturn(loginAttempt);
        Mockito.when(httpServletRequest.getSession().getAttribute(SESSION_USER_RESPONSE_CAPTCHA_ENABLED))
            .thenReturn(userResponseCaptchaEnabled);
        Mockito.when(httpServletRequest.getSession().getAttribute(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES))
            .thenReturn(userResponseEnforceAfterNoOfFailures);
    }
}
