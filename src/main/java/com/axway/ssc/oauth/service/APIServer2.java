package com.axway.ssc.oauth.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

import com.axway.ssc.oauth.shared.ConfigLoad;

/**
 * 
 * OAuth2.0 Released under the same license as scribe (MIT License)
 * 
 * @author cmanda
 * 
 *         This code borrows from and modifies changes made by @yincrash & @houman001
 * @author houman001, yincrash
 * 
 */
public class APIServer2 extends DefaultApi20 {
	private static final String AUTHORIZE_URL = ConfigLoad
			.get("AUTHZ_ENDPOINT");
	private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL
			+ "&scope=%s";

	private static final String SUFFIX_OFFLINE = "";

	@Override
	public String getAccessTokenEndpoint() {
		return ConfigLoad.get("ACCESSTOKEN_ENDPOINT");
	}

	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new AccessTokenExtractor() {

			public Token extract(String response) {

				// System.out.println("To be extracted Response: \n" +
				// response);
				Preconditions
						.checkEmptyString(response,
								"Response body is incorrect. Can't extract a token from an empty string");

				Matcher matcher = Pattern.compile(
						"\"access_token\":\"([^&\"]+)\"").matcher(response);
				if (matcher.find()) {
					System.out.println("Found a match for the access token: ");
					String token = OAuthEncoder.decode(matcher.group(1));
					return new Token(token, "", response);
				} else {
					throw new OAuthException(
							"Response body is incorrect. Can't extract a token from this: '"
									+ response + "'", null);
				}
			}
		};
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		// Append scope if present
		if (config.hasScope()) {
			String format = config.isOffline() ? SCOPED_AUTHORIZE_URL
					+ SUFFIX_OFFLINE : SCOPED_AUTHORIZE_URL;
			return String.format(format, config.getApiKey(),
					OAuthEncoder.encode(config.getCallback()),
					OAuthEncoder.encode(config.getScope()));
		} else {
			String format = config.isOffline() ? AUTHORIZE_URL + SUFFIX_OFFLINE
					: AUTHORIZE_URL;
			return String.format(format, config.getApiKey(),
					OAuthEncoder.encode(config.getCallback()));
		}
	}

	@Override
	public Verb getAccessTokenVerb() {
		return Verb.POST;
	}

	@Override
	public OAuthService createService(OAuthConfig config) {
		return new APIServerOAuth2Service(this, config);
	}

	/**
	 * Adding own functionality for the OAuth2.0 implementation, specific to the
	 * API Server
	 * 
	 * This is to override the BASE scribe functionality, and exact
	 * implementation of the Axway API Server implementation of OAuth 2.0
	 * 
	 * 
	 * @author cmanda
	 * 
	 */
	private static class APIServerOAuth2Service extends OAuth20ServiceImpl {

		private final APIServer2 api;
		private final OAuthConfig config;


		public APIServerOAuth2Service(APIServer2 api, OAuthConfig config) {
			super(api, config);
			this.api = api;
			this.config = config;
		}

		@Override
		/**
		 * Different mechanisms of retrieving the access token, GET/POST
		 */
		public Token getAccessToken(Token requestToken, Verifier verifier) {
			OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(),
					api.getAccessTokenEndpoint());
			switch (api.getAccessTokenVerb()) {
			case POST:
				request.addBodyParameter(OAuthConstants.CLIENT_ID,
						config.getApiKey());
				// API Secret is optional
				if (config.getApiSecret() != null
						&& config.getApiSecret().length() > 0)
					request.addBodyParameter(OAuthConstants.CLIENT_SECRET,
							config.getApiSecret());
				if (requestToken == null) {
					request.addBodyParameter(OAuthConstants.CODE,
							verifier.getValue());
					request.addBodyParameter(OAuthConstants.REDIRECT_URI,
							config.getCallback());
					request.addBodyParameter(OAuthConstants.GRANT_TYPE,
							OAuthConstants.GRANT_TYPE_AUTHORIZATION_CODE);
				} else {
					request.addBodyParameter(OAuthConstants.REFRESH_TOKEN,
							requestToken.getSecret());
					request.addBodyParameter(OAuthConstants.GRANT_TYPE,
							OAuthConstants.GRANT_TYPE_REFRESH_TOKEN);
				}
				break;
			case GET:
			default:
				request.addQuerystringParameter(OAuthConstants.CLIENT_ID,
						config.getApiKey());
				// API Secret is optional
				if (config.getApiSecret() != null
						&& config.getApiSecret().length() > 0)
					request.addQuerystringParameter(
							OAuthConstants.CLIENT_SECRET, config.getApiSecret());
				request.addQuerystringParameter(OAuthConstants.CODE,
						verifier.getValue());
				request.addQuerystringParameter(OAuthConstants.REDIRECT_URI,
						config.getCallback());
				if (config.hasScope())
					request.addQuerystringParameter(OAuthConstants.SCOPE,
							config.getScope());
			}
			Response response = request.send();
			return api.getAccessTokenExtractor().extract(response.getBody());
		}

		@Override
		/**
		 * Any changes to the a specific signing mechanism, should be addressed here.
		 * Going with the default way in the example.
		 */
		public void signRequest(Token accessToken, OAuthRequest request) {

			super.signRequest(accessToken, request);
		}

	}

}
