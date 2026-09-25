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

package org.eclipse.ecsp.oauth2.server.core.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupClientConfig;
import org.eclipse.ecsp.oauth2.server.core.response.dto.UserAttributeDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Service responsible for fetching dynamic user attributes from user-management
 * and adding them to the sign-up model, respecting per-client skip lists stored
 * in the cached client details payload.
 */
@Service
public class SignupAttributeService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignupAttributeService.class);

    static final String SIGNUP_ADDITIONAL_ATTRIBUTES = "signupAdditionalAttributes";
    static final String SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED = "signupAdditionalAttributesEnabled";
    private static final String SIGNUP_SKIP_ATTRIBUTES_KEY = "signupSkipAttributes";

    private final UserManagementClient userManagementClient;
    private final CacheClientUtils cacheClientUtils;
    private final TenantConfigurationService tenantConfigurationService;
    private final ObjectMapper objectMapper;

    /**
     * Constructs a {@code SignupAttributeService}.
     *
     * @param userManagementClient       the client for user-management service calls
    * @param cacheClientUtils            the cache-backed client details lookup
     * @param tenantConfigurationService the service to read per-client signup config
     */
    public SignupAttributeService(UserManagementClient userManagementClient,
            CacheClientUtils cacheClientUtils,
            TenantConfigurationService tenantConfigurationService) {
        this.userManagementClient = userManagementClient;
        this.cacheClientUtils = cacheClientUtils;
        this.tenantConfigurationService = tenantConfigurationService;
        this.objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * Fetches dynamic user attributes from user-management, removes any attributes
     * that are in the per-client skip list, and adds the result to the model.
     *
     * <p>The model is updated with:
     * <ul>
     *   <li>{@code signupAdditionalAttributes} – {@code List<UserAttributeDto>} of
     *       dynamic attributes to render in the form (may be empty)</li>
     *   <li>{@code signupAdditionalAttributesEnabled} – {@code true} so the template
     *       knows to render the section</li>
     * </ul>
     *
     * @param model    the Spring MVC model to populate
     * @param clientId the OAuth2 client ID from the sign-up request (may be null)
     */
    public void setupSignupAttributes(Model model, String clientId) {
        // Check master feature flag first
        boolean featureEnabled = tenantConfigurationService.getTenantProperties()
                .getSignup().isAdditionalAttributesEnabled();
        if (!featureEnabled) {
            LOGGER.debug("setupSignupAttributes: additional-attributes feature is disabled by tenant config");
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES, Collections.emptyList());
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED, false);
            return;
        }
        if (!StringUtils.hasText(clientId)) {
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES, Collections.emptyList());
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED, false);
            return;
        }
        // No signup-config-list entry for this client: nothing is configured to show, so
        // render none rather than falling through and displaying every dynamic attribute.
        if (tenantConfigurationService.getTenantProperties().getSignupClientConfig(clientId) == null) {
            LOGGER.debug("setupSignupAttributes: no signup-config-list entry for client '{}' - "
                    + "showing no additional attributes", clientId);
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES, Collections.emptyList());
            model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED, false);
            return;
        }
        List<UserAttributeDto> attributes = fetchDynamicAttributes();
        if (!attributes.isEmpty()) {
            // Build combined exclusion: skip-attributes ∪ customAttributeListMap keys
            Set<String> exclusions = new HashSet<>();
            exclusions.addAll(resolveSkipList(clientId));
            exclusions.addAll(resolveCustomAttributeKeys(clientId));
            if (!exclusions.isEmpty()) {
                attributes = attributes.stream()
                        .filter(attr -> !exclusions.contains(attr.getName().toLowerCase()))
                        .toList();
            }
        }
        LOGGER.info("setupSignupAttributes: {} attribute(s) will be shown after filtering",
                attributes.size());
        model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES, attributes);
        model.addAttribute(SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED, !attributes.isEmpty());
        // Warn for any customAttributeListMap key that has no definition in user_attributes
        warnOnUnknownCustomAttributeKeys(clientId);
    }

    /**
     * Logs a WARN for each key in {@code custom-attribute-list-map} that does not exist in the
     * {@code user_attributes} table at all.  Such a key can never be persisted to
     * {@code user_attribute_values} and represents a misconfiguration.
     */
    private void warnOnUnknownCustomAttributeKeys(String clientId) {
        Set<String> mapKeys = resolveCustomAttributeKeys(clientId);
        if (mapKeys.isEmpty()) {
            return;
        }
        List<UserAttributeDto> allAttrs;
        try {
            allAttrs = userManagementClient.getAllUserAttributes();
        } catch (Exception ex) {
            LOGGER.warn("warnOnUnknownCustomAttributeKeys: could not fetch attributes from user-management; "
                    + "skipping validation for client '{}'", clientId, ex);
            return;
        }
        if (allAttrs == null) {
            LOGGER.warn("warnOnUnknownCustomAttributeKeys: could not fetch attributes from "
                    + "user-management; skipping validation for client '{}'", clientId);
            return;
        }
        Set<String> allAttrNames = allAttrs.stream()
                .map(a -> a.getName().toLowerCase())
                .collect(java.util.stream.Collectors.toSet());
        for (String key : mapKeys) {
            if (!allAttrNames.contains(key.toLowerCase())) {
                LOGGER.warn("customAttributeListMap misconfiguration: attribute key '{}' for client '{}' "
                        + "is not defined in user_attributes table — auto-population will fail at signup.",
                        key, clientId);
            }
        }
    }

    /**
     * Validates that every key in {@code custom-attribute-list-map} for the given client
     * exists in the {@code user_attributes} table.  Called during the POST (form submission)
     * flow so that a misconfigured key fails the signup with a clear error rather than
     * silently writing nothing.
     *
     * @param clientId the OAuth2 client ID whose config is being applied
     * @throws IllegalStateException if one or more keys are not defined in {@code user_attributes}
     */
    public void validateCustomAttributeKeys(String clientId) {
        Set<String> mapKeys = resolveCustomAttributeKeys(clientId);
        if (mapKeys.isEmpty()) {
            return;
        }
        List<UserAttributeDto> allAttrs = userManagementClient.getAllUserAttributes();
        if (allAttrs == null) {
            LOGGER.warn("validateCustomAttributeKeys: could not fetch attributes from user-management "
                    + "— skipping key validation for client '{}'", clientId);
            return;
        }
        Set<String> allAttrNames = allAttrs.stream()
                .map(a -> a.getName().toLowerCase())
                .collect(java.util.stream.Collectors.toSet());
        List<String> unknownKeys = mapKeys.stream()
                .filter(k -> !allAttrNames.contains(k.toLowerCase()))
                .toList();
        if (!unknownKeys.isEmpty()) {
            throw new IllegalStateException(
                    "customAttributeListMap: key(s) " + unknownKeys
                    + " for client '" + clientId + "' are not defined in user_attributes table");
        }
    }

    /**
     * Fetches custom signup attributes from user-management.
     * Requests only {@code dynamicAttribute=false} rows directly from the
     * {@code user_attributes} table, so core entity fields (id, user_name, email, etc.)
     * are never included. The {@code mandatory} flag drives required/optional rendering.
     *
     * @return list of custom signup {@link UserAttributeDto}, empty on error
     */
    private List<UserAttributeDto> fetchDynamicAttributes() {
        try {
            List<UserAttributeDto> all = userManagementClient.getUserAttributes();
            if (all == null) {
                LOGGER.warn("fetchDynamicAttributes: user-management returned null (check logs for HTTP error)");
                return Collections.emptyList();
            }
            LOGGER.info("fetchDynamicAttributes: received {} attribute(s) from user-management",
                    all.size());
            return all;
        } catch (Exception ex) {
            LOGGER.error("fetchDynamicAttributes: failed to fetch user attributes from user-management", ex);
            return Collections.emptyList();
        }
    }

    /**
     * Resolves the set of attribute keys defined in {@code custom-attribute-list-map} for the
     * given client. These keys are auto-populated server-side at signup time and must NOT be
     * rendered as form fields in the UI.
     *
     * <p>Format: {@code attrKey#displayName,...} (e.g. {@code custom:companyName#companyName}).
     * The key is the part before the {@code #} separator, lowercased.
     *
     * @param clientId the OAuth2 client ID
     * @return lower-cased set of custom attribute keys; empty set if none or on error
     */
    private Set<String> resolveCustomAttributeKeys(String clientId) {
        Set<String> keys = new HashSet<>();
        try {
            SignupClientConfig config =
                    tenantConfigurationService.getTenantProperties().getSignupClientConfig(clientId);
            if (config != null && StringUtils.hasText(config.getCustomAttributeListMap())) {
                Arrays.stream(config.getCustomAttributeListMap().split(","))
                        .map(String::trim)
                        .filter(StringUtils::hasText)
                        .forEach(entry -> {
                            // Key is the part before '#'; part after '#' is display name
                            int hashIdx = entry.indexOf('#');
                            if (hashIdx > 0) {
                                keys.add(entry.substring(0, hashIdx).trim().toLowerCase());
                            }
                        });
            }
        } catch (Exception ex) {
            LOGGER.warn("Could not resolve custom attribute keys for client '{}': {}",
                    clientId, ex.getMessage());
        }
        return keys;
    }

    /**
     * Resolves the combined set of attribute names that should be hidden on the sign-up form
     * for the given client. Two sources are merged:
     * <ol>
     *   <li><b>Properties-based</b> – comma-separated {@code skip-attributes} from the matching
     *       entry in {@code tenant.props.*.signup-config-list}.</li>
     *   <li><b>DB-based (legacy)</b> – JSON array {@code signupSkipAttributes} stored in
     *       {@code RegisteredClientDetails.additionalInformation}.</li>
     * </ol>
     * All names are normalised to lower-case so the filter is case-insensitive.
     *
     * @param clientId the OAuth2 client ID
     * @return lower-cased set of attribute names to skip; empty set if none or on error
     */
    private Set<String> resolveSkipList(String clientId) {
        Set<String> merged = new HashSet<>();

        // Source 1: properties-based skip list from signup-config-list
        try {
            SignupClientConfig config =
                    tenantConfigurationService.getTenantProperties().getSignupClientConfig(clientId);
            if (config != null && StringUtils.hasText(config.getSkipAttributes())) {
                Arrays.stream(config.getSkipAttributes().split(","))
                        .map(String::trim)
                        .filter(StringUtils::hasText)
                        .map(String::toLowerCase)
                        .forEach(merged::add);
            }
        } catch (Exception ex) {
            LOGGER.warn("Could not resolve properties skip-list for client '{}': {}", clientId, ex.getMessage());
        }

        // Source 2: cached skip list from the cached client payload
        try {
            ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(clientId);
            if (clientDetails != null && StringUtils.hasText(clientDetails.getAdditionalInformation())) {
                com.fasterxml.jackson.databind.JsonNode root =
                        objectMapper.readTree(clientDetails.getAdditionalInformation());
                com.fasterxml.jackson.databind.JsonNode skipNode = root.get(SIGNUP_SKIP_ATTRIBUTES_KEY);
                if (skipNode != null && skipNode.isArray()) {
                    Set<String> dbSkip = objectMapper.convertValue(skipNode,
                            new TypeReference<Set<String>>() { });
                    dbSkip.stream()
                            .filter(StringUtils::hasText)
                            .map(String::toLowerCase)
                            .forEach(merged::add);
                }
            }
        } catch (Exception ex) {
            LOGGER.warn("Could not resolve DB skip-list for client '{}': {}", clientId, ex.getMessage());
        }

        LOGGER.debug("Resolved skip-list for client '{}': {}", clientId, merged);
        return merged;
    }
}
