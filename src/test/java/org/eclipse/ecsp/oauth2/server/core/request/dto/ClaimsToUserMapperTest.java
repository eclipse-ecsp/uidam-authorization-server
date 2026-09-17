package org.eclipse.ecsp.oauth2.server.core.request.dto;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.request.dto.ClaimsToUserMapper.UserField;
import org.eclipse.ecsp.oauth2.server.core.request.transformer.DefaultIdpTransformer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClaimsToUserMapperTest {

    @Mock
    private DefaultIdpTransformer defaultTransformer;

    @InjectMocks
    private ClaimsToUserMapper claimsToUserMapper;

    private ExternalIdpRegisteredClient idpConfig;
    private Map<String, Object> claims;

    @BeforeEach
    void setUp() {
        // Initialize test data
        idpConfig = new ExternalIdpRegisteredClient();
        idpConfig.setRegistrationId("test-idp");

        Map<String, String> mappings = new HashMap<>();
        mappings.put("USERNAME", "preferred_username");
        mappings.put("EMAIL", "email");
        mappings.put("FIRSTNAME", "given_name");
        mappings.put("LASTNAME", "family_name");
        idpConfig.setMappings(mappings);

        claims = new HashMap<>();
        claims.put("preferred_username", "testuser");
        claims.put("email", "test@example.com");
        claims.put("given_name", "Test");
        claims.put("family_name", "User");
    }

    private void setupDefaultTransformer() {
        when(defaultTransformer.transformUserName(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformEmail(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformFirstName(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformLastName(any())).thenAnswer(i -> i.getArgument(0));
    }

    @Test
    void mapClaimsToUserRequest_WithValidData_ShouldMapCorrectly() {
        // Given
        setupDefaultTransformer();

        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then
        assertNotNull(result);
        assertEquals("testuser", result.getUserName());
        assertEquals("test@example.com", result.getEmail());
        assertEquals("Test", result.getFirstName());
        assertEquals("User", result.getLastName());
        assertEquals("test-idp", result.getIdentityProviderName());
        assertEquals("ACTIVE", result.getStatus());
    }

    @Test
    void mapClaimsToUserRequest_WithGoogleIdp_ShouldUseGoogleTransformer() {
        // Given
        idpConfig.setRegistrationId("google");

        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then
        assertNotNull(result);
        assertEquals("google", result.getIdentityProviderName());
    }

    @Test
    void mapClaimsToUserRequest_WithNullClaims_ShouldSkipMapping() {
        // Given
        claims.put("email", null);
        when(defaultTransformer.transformUserName(any())).thenReturn("testuser");

        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then
        assertNotNull(result);
        assertNull(result.getEmail());
        assertEquals("testuser", result.getUserName());
    }

    @Test
    void mapClaimsToUserRequest_WithInvalidFieldName_ShouldNotThrowException() {
        // Given
        Map<String, String> invalidMappings = new HashMap<>();
        invalidMappings.put("INVALID_FIELD", "some_claim");
        idpConfig.setMappings(invalidMappings);

        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);
        // Then
        assertNotNull(result);
        assertEquals("test-idp", result.getIdentityProviderName());
        assertEquals("ACTIVE", result.getStatus());
    }

    @Test
    void mapClaimsToUserRequest_WithNullParameters_ShouldThrowException() {
        assertThrows(NullPointerException.class, () -> claimsToUserMapper.mapClaimsToUserRequest(null, idpConfig));
        assertThrows(NullPointerException.class, () -> claimsToUserMapper.mapClaimsToUserRequest(claims, null));
    }

    @Test
    void mapClaimsToUserRequest_WithEmptyMappings_ShouldReturnBasicUser() {
        // Given
        idpConfig.setMappings(Collections.emptyMap());

        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then
        assertNotNull(result);
        assertEquals("test-idp", result.getIdentityProviderName());
        assertEquals("ACTIVE", result.getStatus());
    }

    @Test
    void mapClaimsToUserRequest_WithAllUserFields_ShouldMapAllFields() {
        // Given
        Map<String, String> allMappings = new HashMap<>();
        for (UserField field : UserField.values()) {
            allMappings.put(field.name(), field.getFieldName().toLowerCase());
            claims.put(field.getFieldName().toLowerCase(), "test_" + field.name().toLowerCase());
        }
        idpConfig.setMappings(allMappings);
        when(defaultTransformer.transformUserName(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformEmail(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformFirstName(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformLastName(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformCountry(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformState(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformCity(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformAddress1(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformAddress2(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformPostalCode(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformPhoneNumber(any())).thenAnswer(i -> i.getArgument(0));
        when(defaultTransformer.transformGender(any())).thenAnswer(i -> i.getArgument(0));
        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then
        assertNotNull(result);
        assertEquals("test_username", result.getUserName());
        assertEquals("test_email", result.getEmail());
        assertEquals("test_firstname", result.getFirstName());
        assertEquals("test_lastname", result.getLastName());
        assertEquals("test_country", result.getCountry());
        assertEquals("test_state", result.getState());
        assertEquals("test_city", result.getCity());
        assertEquals("test_address1", result.getAddress1());
        assertEquals("test_address2", result.getAddress2());
        assertEquals("test_postalcode", result.getPostalCode());
        assertEquals("test_phonenumber", result.getPhoneNumber());
        assertEquals("test_gender", result.getGender());
    }

    @Test
    void setFieldValue_WithInvalidFieldName_StoresAsDynamicAttribute() {
        // Given
        Map<String, String> invalidMappings = new HashMap<>();
        invalidMappings.put("INVALID_FIELD", "some_claim");
        idpConfig.setMappings(invalidMappings);
        claims.put("some_claim", "test_value");

        // When
        FederatedUserDto result = claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig);

        // Then - unknown field names are routed to additionalAttributes instead of throwing
        assertNotNull(result);
        assertEquals("test_value", result.getAdditionalAttributes().get("INVALID_FIELD"));
    }

    @Test
    void setFieldValue_WithNullTransformedValue() {
        // Given
        Map<String, String> mappings = new HashMap<>();
        mappings.put("USERNAME", "username");
        idpConfig.setMappings(mappings);
        claims.put("username", "test_value");
        
        // Mock transformer to return null
        when(defaultTransformer.transformUserName(any())).thenReturn(null);

        // When & Then
        assertNotNull(claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig));
    }

    @Test
    void setFieldValue_WithTransformerException_ShouldThrowIllegalStateException() {
        // Given
        Map<String, String> mappings = new HashMap<>();
        mappings.put("USERNAME", "username");
        idpConfig.setMappings(mappings);
        claims.put("username", "test_value");
        
        // Mock transformer to throw exception
        when(defaultTransformer.transformUserName(any()))
            .thenThrow(new RuntimeException("Transformer error"));

        // When & Then
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig));
        assertEquals("Failed to set field 'USERNAME' during claims transformation", 
            exception.getMessage());
    }

    @Test
    void setFieldValue_WithNullFieldName_ShouldThrowNullPointerException() {
        // Given
        Map<String, String> mappings = new HashMap<>();
        mappings.put(null, "username");
        idpConfig.setMappings(mappings);
        claims.put("username", "test_value");

        // When & Then
        assertThrows(NullPointerException.class, 
            () -> claimsToUserMapper.mapClaimsToUserRequest(claims, idpConfig));
    }
}