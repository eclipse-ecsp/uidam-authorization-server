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

package org.eclipse.ecsp.oauth2.server.core.authentication.tokens;


import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

/**
 * CustomUserPwdAuthenticationTokenDeserializer is a class that extends the JsonDeserializer class from the Jackson
 * library. It is used to deserialize JSON into CustomUserPwdAuthenticationToken objects.
 */
class CustomUserPwdAuthenticationTokenDeserializer extends JsonDeserializer<CustomUserPwdAuthenticationToken> {

    private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST =
        new TypeReference<List<GrantedAuthority>>() {};

    private static final TypeReference<Object> OBJECT = new TypeReference<Object>() {
    };

    /**
     * This method overrides the deserialize method from the superclass.
     * It deserializes JSON into a CustomUserPwdAuthenticationToken object.
     *
     * @param jp the JSON parser.
     * @param ctxt the deserialization context.
     * @return a CustomUserPwdAuthenticationToken object.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public CustomUserPwdAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt)
            throws IOException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);
        Boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
        JsonNode principalNode = readJsonNode(jsonNode, "principal");
        Object principal = getPrincipal(mapper, principalNode);
        JsonNode credentialsNode = readJsonNode(jsonNode, "credentials");
        Object credentials = getCredentials(credentialsNode);
        JsonNode accountNameNode = readJsonNode(jsonNode, "accountName");
        String accountName = getAccountName(accountNameNode);
        JsonNode accountIdNode = readJsonNode(jsonNode, "accountId");
        String accountId = getAccountName(accountIdNode); // reuse same null/text extraction
        JsonNode mfaRequiredNode = readJsonNode(jsonNode, "mfaRequired");
        Boolean mfaRequired = (!mfaRequiredNode.isNull() && !mfaRequiredNode.isMissingNode())
                ? mfaRequiredNode.asBoolean() : null;
        List<GrantedAuthority> authorities = mapper.readValue(readJsonNode(jsonNode, "authorities").traverse(mapper),
                GRANTED_AUTHORITY_LIST);
        CustomUserPwdAuthenticationToken token = (!authenticated)
                ? CustomUserPwdAuthenticationToken.unauthenticated(principal, credentials, accountName)
                : CustomUserPwdAuthenticationToken.authenticated(principal, credentials, accountName, accountId,
                        mfaRequired, authorities);
        JsonNode detailsNode = readJsonNode(jsonNode, "details");
        if (detailsNode.isNull() || detailsNode.isMissingNode()) {
            token.setDetails(null);
        } else {
            Object details = mapper.readValue(detailsNode.toString(), OBJECT);
            token.setDetails(details);
        }
        return token;
    }

    /**
     * This method gets the credentials from a JSON node.
     *
     * @param credentialsNode the JSON node containing the credentials.
     * @return the credentials as a string, or null if the node is null or missing.
     */
    private Object getCredentials(JsonNode credentialsNode) {
        if (credentialsNode.isNull() || credentialsNode.isMissingNode() || !credentialsNode.isTextual()) {
            return null;
        }
        return credentialsNode.asText();
    }

    /**
     * This method gets the principal from a JSON node.
     *
     * @param mapper the object mapper.
     * @param principalNode the JSON node containing the principal.
     * @return the principal as an object, or as a string if the node is an object.
     * @throws IOException if an I/O error occurs.
     */
    private Object getPrincipal(ObjectMapper mapper, JsonNode principalNode)
            throws IOException {
        if (principalNode.isNull() || principalNode.isMissingNode() || !principalNode.isTextual()) {
            return null;
        } else if (principalNode.isObject()) {
            return mapper.readValue(principalNode.traverse(mapper), Object.class);
        }
        return principalNode.asText();
    }

    /**
     * This method gets the account name from a JSON node.
     *
     * @param accountNameNode the JSON node containing the account name.
     * @return the account name as a string, or null if the node is null or missing.
     */
    private String getAccountName(JsonNode accountNameNode) {
        if (accountNameNode.isNull() || accountNameNode.isMissingNode() || !accountNameNode.isTextual()) {
            return null;
        }
        return accountNameNode.asText();
    }

    /**
     * This method reads a JSON node.
     *
     * @param jsonNode the JSON node.
     * @param field the field to read from the JSON node.
     * @return the JSON node for the field, or a missing node if the field does not exist.
     */
    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}