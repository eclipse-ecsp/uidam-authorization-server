package org.eclipse.ecsp.oauth2.server.core.request.dto;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

/**
 * BaseUserDto.
 */
@Getter
@Setter
public class BaseUserDto {
    private String userName;
    private String lastName;
    private String country;
    private String state;
    private String city;
    @NotNull
    @Email
    private String email;
    private String status;
    private String aud;
    @NotNull
    private String firstName;
    private String address1;
    private String address2;
    private String postalCode;
    private String phoneNumber;
    private String gender;

    @Setter(AccessLevel.NONE)
    private Map<String, Object> additionalAttributes = new HashMap<>();

    @JsonAnyGetter
    public Map<String, Object> getAdditionalAttributes() {
        return additionalAttributes;
    }

    @JsonAnySetter
    public void setAdditionalAttributes(String name, Object value) {
        additionalAttributes.put(name, value);
    }
}
