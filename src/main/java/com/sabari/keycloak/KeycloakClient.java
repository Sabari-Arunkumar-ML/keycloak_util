package com.sabari.keycloak;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.http.client.HttpClient;

public class KeycloakClient {


    private static String KEYCLOAK_BASE_URL = String.format("%s://%s:%s", KeycloakClientConstants.KEYCLOAK_HTTP_PROTOCOL, KeycloakClientConstants.KEYCLOAK_HOST, KeycloakClientConstants.KEYCLOAK_PORT);
    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakClient.class);

    
    

    private static CloseableHttpClient getHttpClient() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial((chain, authType) -> true).build();
        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
        return httpClient;
    }

    private static String sendHttpRequest(HttpClient httpClient,
                String httpMethod,
                String url, 
                String accessToken) throws Exception {
        String responseBody = null;
       
        HttpResponse httpResponse = null;

        switch (httpMethod) {
            case KeycloakClientConstants.HTTP_METHOD_GET:
                HttpGet httpGet = new HttpGet(url);
                // httpGet.setHeader(HttpHeaders.CONTENT_TYPE, contentType);
                httpGet.setHeader(HttpHeaders.AUTHORIZATION,  String.format("%s %s", KeycloakClientConstants.BEARER_TOKEN_AUTH_KEY, accessToken));
                httpResponse = httpClient.execute(httpGet);
                break;
        }
        if (httpResponse != null) {
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            responseBody = null;
            if (httpResponse.getEntity() != null) {
                responseBody = EntityUtils.toString(httpResponse.getEntity());
            }
            if (statusCode == HttpStatus.SC_OK ) {
                return responseBody;
            } else {
                LOGGER.error("Failed to get UserInfo from keycloak; Status code: {}; URL: {}; Response: {}", statusCode , url, responseBody);
                if (statusCode == HttpStatus.SC_FORBIDDEN ) {
                    LOGGER.error("Token might probably lack required scope/permission for the user or not associated with user");
                } else if (statusCode == HttpStatus.SC_UNAUTHORIZED ) {
                    LOGGER.error("Token might have expired");
                }
                responseBody = null;
            }
        } else {
            LOGGER.error("UserInfo request execution is unsuccessful; URL: {};", url);
        }
    
        return responseBody;
    }
    private static Map<String, ArrayList<String>>  getGroupsAndRolePermissionForAssociatedUser(String accessToken) throws Exception{
       
        Map<String, ArrayList<String>> resourcePermissionMapping = new HashMap<>();
        if (accessToken == null) {
            LOGGER.error("AccessToken is expected");
            return null;
        }
        String OPENID_USERINFO_ENDPOINT_URL = String.format("%s/%s", KEYCLOAK_BASE_URL, KeycloakClientConstants.OPENID_USERINFO_ENDPOINT);
        // Client can be re-used in future
        try (CloseableHttpClient httpClient = getHttpClient()) {
            String responseBody = sendHttpRequest(httpClient, KeycloakClientConstants.HTTP_METHOD_GET, OPENID_USERINFO_ENDPOINT_URL, accessToken);
            if (responseBody != null) {
                LOGGER.debug("responseBody: {} ", responseBody);
                try {
                    ObjectMapper objectMapper = new ObjectMapper();
                    JsonNode jsonNode = objectMapper.readTree(responseBody);
                    JsonNode accessPermissionsNode = jsonNode.get(KeycloakClientConstants.ACCESS_PERMISSION_CLAIM_IN_KC_USERINFO);
                    if (accessPermissionsNode == null) {
                        LOGGER.error("{} is not available in OpenID userInfo response", KeycloakClientConstants.ACCESS_PERMISSION_CLAIM_IN_KC_USERINFO);
                        return null;
                    }
                    resourcePermissionMapping.put(KeycloakClientConstants.ACCESS_PERMISSION_CLAIM_IN_VMANAGE, new ArrayList<>(List.of(objectMapper.treeToValue(accessPermissionsNode, String[].class))));

                    JsonNode groupNode = jsonNode.get(KeycloakClientConstants.GROUP_CLAIM_IN_KC_USERINFO);
                    if (groupNode == null) {
                        LOGGER.error("{} is not available in OpenID userInfo response", KeycloakClientConstants.GROUP_CLAIM_IN_KC_USERINFO);
                        return null;
                    }
                    String[] roles = objectMapper.treeToValue(groupNode, String[].class);
                    resourcePermissionMapping.put(KeycloakClientConstants.GROUP_CLAIM_IN_VMANAGE, new ArrayList<>(List.of(roles)));

                } catch (Exception e) {
                    LOGGER.error("UserInfo response is not in expected format: {}", e.toString());
                    return null;
                }
            }
        } catch (Exception e) {
            LOGGER.error("caught exeption while creating Keycloak client {}", e.toString());
        }
        
        return resourcePermissionMapping;
    }
    public static void main(String[] args) {
        // Input accessToken [forwarded by envoy]
        // Token with open ID claim
        String accessToken = "-";
        try {
            // null value returns on unsuccessful fetch/processing of Keycloak UserInfo response
           getGroupsAndRolePermissionForAssociatedUser(accessToken);
        }catch (Exception e){
            LOGGER.error("caught exeption while getting roles/permissions from Keycloak {}", e.toString());
        }
    }
}

