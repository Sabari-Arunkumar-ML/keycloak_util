package com.sabari.keycloak;

public final class KeycloakClientConstants {
    static final String KEYCLOAK_HOST = "172.18.40.70";
    static final String KEYCLOAK_PORT = "9235";
    static final String KEYCLOAK_HTTP_PROTOCOL = "https";
    static final String BEARER_TOKEN_AUTH_KEY = "Bearer";
    static final String SPACE_CHAR = " ";
    static final String HTTP_METHOD_GET = "GET";
    static final String OPENID_USERINFO_ENDPOINT = "realms/master/protocol/openid-connect/userinfo";
    static final String ACCESS_PERMISSION_CLAIM_IN_KC_USERINFO = "vmanage_access_permissions";    
    static final String ACCESS_PERMISSION_CLAIM_IN_VMANAGE = "userRoles";
    static final String GROUP_CLAIM_IN_KC_USERINFO = "vmanage_groups";    
    static final String GROUP_CLAIM_IN_VMANAGE = "userGroups";

}
