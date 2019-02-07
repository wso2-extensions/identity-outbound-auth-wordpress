package org.wso2.carbon.identity.authenticator.wordpress;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.wordpress.internal.WordpressAuthenticatorServiceComponent;
import org.osgi.service.component.ComponentContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, AuthenticatedUser.class,
        OAuthClientRequest.class, URL.class})
public class WordpressAuthenticatorTest {

    @Mock
    OAuthClientResponse oAuthClientResponse;
    @Mock
    HttpServletRequest httpServletRequest;
    @Mock
    OAuthAuthzResponse mockOAuthAuthzResponse;
    @Spy
    private AuthenticationContext context = new AuthenticationContext();
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private OAuthClient mockOAuthClient;
    @Mock
    ComponentContext componentContext;
    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;
    WordpressAuthenticator wordpressAuthenticator;
    WordpressAuthenticatorServiceComponent wordpressAuthenticatorServiceComponent;

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        authenticatorProperties.put("scope", "");
        return new Object[][]{{authenticatorProperties}};
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {
        wordpressAuthenticator = new WordpressAuthenticator();
        wordpressAuthenticatorServiceComponent = new WordpressAuthenticatorServiceComponent();
        initMocks(this);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndpoint = wordpressAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(WordpressAuthenticatorConstants.WORDPRESS_TOKEN_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for getUserInfoEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndpoint = wordpressAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(WordpressAuthenticatorConstants.WORDPRESS_USERINFO_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for requiredIDToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIDToken(Map<String, String> authenticatorProperties) {
        Assert.assertFalse(wordpressAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {
        Assert.assertEquals(WordpressAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME,
                wordpressAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        Assert.assertEquals(WordpressAuthenticatorConstants.WORDPRESS_OAUTH_ENDPOINT,
                wordpressAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for getName method")
    public void testGetName() {
        Assert.assertEquals(WordpressAuthenticatorConstants.AUTHENTICATOR_NAME, wordpressAuthenticator.getName());
    }

    @Test(description = "Test case for getConfigurationProperties(")
    public void testGetConfigurationProperties() {
        Assert.assertEquals(3, wordpressAuthenticator.getConfigurationProperties().size());
    }

    @Test(expectedExceptions = NullPointerException.class,
            description = "Negative Test case for processAuthenticationResponse", dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        WordpressAuthenticator spyAuthenticator = PowerMockito.spy(new WordpressAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for getOauthResponse method")
    public void testGetOauthResponse() throws Exception {
        OAuthClientResponse oAuthClientResponse = GetOauthResponse(mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(oAuthClientResponse);
    }

    public OAuthClientResponse GetOauthResponse(OAuthClient mockOAuthClient, OAuthClientRequest mockOAuthClientRequest)
            throws Exception {
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        OAuthClientResponse oAuthClientResponse = Whitebox.invokeMethod(wordpressAuthenticator,
                "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        return oAuthClientResponse;
    }

    @Test(description = "Test case for wordpressAuthenticatorServiceComponent activate and deactivate method")
    public void testYammerAuthenticatorServiceComponentDeactivateAndActivate() throws Exception {
        Whitebox.invokeMethod(wordpressAuthenticatorServiceComponent, "activate", componentContext);
        Whitebox.invokeMethod(wordpressAuthenticatorServiceComponent, "deactivate", componentContext);
    }
}
