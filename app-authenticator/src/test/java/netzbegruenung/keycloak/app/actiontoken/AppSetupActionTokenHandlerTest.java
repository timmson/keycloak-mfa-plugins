/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package netzbegruenung.keycloak.app.actiontoken;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("AppSetupActionTokenHandler")
@ExtendWith(MockitoExtension.class)
class AppSetupActionTokenHandlerTest {

	private AppSetupActionTokenHandler handler;

	@Mock
	private ActionTokenContext<AppSetupActionToken> tokenContext;

	@Mock
	private AppSetupActionToken token;

	@Mock
	private KeycloakSession session;

	@Mock
	private RealmModel realm;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private UserModel user;

	@Mock
	private CredentialProvider credentialProvider;

	@Mock
	private org.keycloak.models.SubjectCredentialManager credentialManager;

	@Mock
	private ClientModel clientModel;

	@Mock
	private org.keycloak.models.KeycloakContext keycloakContext;

	@Mock
	private CredentialModel credentialModel;

	@Mock
	private UriInfo uriInfo;

	@Mock
	private AuthenticationSessionProvider authenticationSessionProvider;

	@Mock
	private RootAuthenticationSessionModel rootAuthenticationSessionModel;

	@Mock
	private AuthenticationSessionModel authenticationSessionModel;

	@BeforeEach
	void setUp() {
		handler = new AppSetupActionTokenHandler();
	}

	@Test
	@DisplayName("should create credential and return 201 when setup is successful")
	void shouldCreateCredentialAndReturn201WhenSetupIsSuccessful() {
		String originalSessionId = "original-session";

		MultivaluedMap<String, String> queryParameters = new MultivaluedHashMap<>();
		queryParameters.add("device_id", "device-123");
		queryParameters.add("device_os", "Android");
		queryParameters.add("public_key", "test-public-key");
		queryParameters.add("key_algorithm", "RSA");
		queryParameters.add("signature_algorithm", "SHA256withRSA");
		queryParameters.add("device_push_id", "push-token-456");

		HttpRequest httpRequest = mock(HttpRequest.class);
		when(uriInfo.getQueryParameters()).thenReturn(queryParameters);
		when(httpRequest.getUri()).thenReturn(uriInfo);
		when(tokenContext.getRequest()).thenReturn(httpRequest);
		when(tokenContext.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthenticatedUser()).thenReturn(user);
		when(tokenContext.getSession()).thenReturn(session);
		when(user.credentialManager()).thenReturn(credentialManager);
		when(realm.getClientById(any())).thenReturn(null);
		when(token.getOriginalAuthenticationSessionId()).thenReturn(originalSessionId);
		when(realm.getClientById(any())).thenReturn(clientModel);
		when(tokenContext.getRealm()).thenReturn(realm);
		when(session.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID)).thenReturn(credentialProvider);
		when(credentialModel.getCredentialData()).thenReturn("{\"publicKey\":\"other-key\",\"deviceId\":\"other-device\",\"deviceOs\":\"iOS\",\"keyAlgorithm\":\"RSA\",\"signatureAlgorithm\":\"SHA256withRSA\",\"devicePushId\":\"other-push\"}");
		when(credentialManager.getStoredCredentialsByTypeStream(AppCredentialModel.TYPE)).thenReturn(Stream.of(credentialModel));
		when(session.authenticationSessions()).thenReturn(authenticationSessionProvider);
		when(authenticationSessionProvider.getRootAuthenticationSession(eq(realm), eq(originalSessionId))).thenReturn(rootAuthenticationSessionModel);
		when(rootAuthenticationSessionModel.getAuthenticationSession(eq(clientModel), nullable(String.class))).thenReturn(authenticationSessionModel);

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(201, response.getStatus());
		verify(credentialProvider).createCredential(eq(realm), eq(user), any(AppCredentialModel.class));
	}

	// Token usage tests
	@Test
	@DisplayName("should not allow repeated token usage")
	void shouldNotAllowRepeatedTokenUsage() {
		boolean canReuse = handler.canUseTokenRepeatedly(token, tokenContext);

		assertFalse(canReuse);
	}
}
