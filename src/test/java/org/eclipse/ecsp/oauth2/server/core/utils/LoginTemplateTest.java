/*
 * Copyright (c) 2026 Harman International
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Renders the login template to verify its conditional authentication controls.
 */
class LoginTemplateTest {

    private String render(boolean internal, boolean external, boolean redirect,
                          boolean account, boolean captcha, boolean signup) {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("templates/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode("HTML");
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(resolver);

        MockServletContext servletContext = new MockServletContext();
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        request.setRequestURI("/ecsp/login");
        JakartaServletWebApplication application = JakartaServletWebApplication.buildApplication(servletContext);
        WebContext context = new WebContext(application.buildExchange(request, new MockHttpServletResponse()),
            Locale.ENGLISH);
        context.setVariables(Map.ofEntries(
            Map.entry("isInternalLoginEnabled", internal),
            Map.entry("isExternalIdpEnabled", external),
            Map.entry("isIDPAutoRedirectionEnabled", redirect),
            Map.entry("isAccountFieldEnabled", account),
            Map.entry("isCaptchaFieldEnabled", captcha),
            Map.entry("isSignUpEnabled", signup),
            Map.entry("issuer", "ecsp"),
            Map.entry("externalIdpAuthorizationUri", "/oauth2/authorization/"),
            Map.entry("tenantStylesheetPath", "/css/style.css"),
            Map.entry("captchaSite", "test-site-key"),
            Map.entry("client_id", "test-client")));
        ExternalIdpRegisteredClient provider = new ExternalIdpRegisteredClient();
        provider.setRegistrationId("Microsoft");
        provider.setClientName("Microsoft (Harman Azure AD)");
        context.setVariable("externalIdpList", external ? List.of(provider) : List.of());
        return engine.process("login", context);
    }

    @Test
    void shouldRenderMixedLoginWithOptionalControls() {
        String html = render(true, true, false, true, true, true);
        assertTrue(html.contains("href=\"/css/style.css\""));
        assertFalse(html.contains("login.css"));
        assertTrue(html.contains("src=\"/images/ecsp-logo.svg\""));
        assertTrue(html.contains("Sign in with your SSO"));
        assertTrue(html.contains("action=\"/login\""));
        assertTrue(html.contains("name=\"username\""));
        assertTrue(html.contains("name=\"password\""));
        assertTrue(html.contains("name=\"account_name\""));
        assertTrue(html.contains("id=\"toggleAccountName\""));
        assertTrue(html.contains("aria-expanded=\"false\" aria-controls=\"accountNameFields\""));
        assertTrue(html.contains("id=\"accountNameFields\" class=\"container-auth-input2\" hidden"));
        assertTrue(html.contains("id=\"g-recaptcha\""));
        assertTrue(html.contains("/ecsp/sign-up?client_id=test-client"));
        assertTrue(html.contains("/ecsp/recovery"));
        assertTrue(html.contains("/ecsp/oauth2/authorization/ecsp-Microsoft"));
        assertTrue(html.contains("/images/microsoft.png"));
        assertTrue(html.indexOf("class=\"login-sso\"") < html.indexOf("class=\"login-form\""));
        for (String field : List.of("client_id", "scope", "redirect_uri", "response_type",
                "state", "issuer", "tenantId")) {
            assertTrue(html.contains("type=\"hidden\" name=\"" + field + "\""));
        }
    }

    @Test
    void shouldRenderInternalOnlyWithoutOptionalControls() {
        String html = render(true, false, false, false, false, false);
        assertTrue(html.contains("class=\"login-form\""));
        assertFalse(html.contains("class=\"login-sso\""));
        assertFalse(html.contains("name=\"account_name\""));
        assertFalse(html.contains("id=\"toggleAccountName\""));
        assertFalse(html.contains("id=\"g-recaptcha\""));
        assertFalse(html.contains("id=\"sign-up\""));
    }

    @Test
    void shouldRenderExternalOnlyWithoutCredentialForm() {
        String html = render(false, true, false, false, false, false);
        assertTrue(html.contains("class=\"login-sso\""));
        assertFalse(html.contains("class=\"login-form\""));
        assertFalse(html.contains("class=\"login-divider\""));
    }

    @Test
    void shouldPreserveExternalAutoRedirect() {
        String html = render(false, true, true, false, false, false);
        assertTrue(html.contains("http-equiv=\"refresh\""));
        assertTrue(html.contains("0; url=/ecsp/oauth2/authorization/ecsp-Microsoft"));
        assertFalse(html.contains("class=\"login-sso\""));
        assertFalse(html.contains("class=\"login-form\""));
    }
}