package com.axway.ssc.oauth.client;

import java.util.Scanner;

import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.axway.ssc.oauth.service.APIServer2;
import com.axway.ssc.oauth.shared.ConfigLoad;

/**
 * Client implementation for the step-by-step flow of OAuth2.0 with the sample
 * policies that come out of the box with API server.
 * 
 * @author cmanda
 * 
 */
public class APIServer2Client {

	// Just a header for the product/company name
	private static final String NETWORK_NAME = ConfigLoad
			.get("AUTHZ_SERVER_NAME");
	// Protected resources as defined in the policies
	private static final String PROTECTED_RESOURCE_URL = ConfigLoad
			.get("PROTECTED_RESOURCE.1");

	// Defined Scope to be used in the OAuth flow
	private static final String SCOPE = ConfigLoad.get("SCOPE");
	private static final Token EMPTY_TOKEN = null;

	public static void main(String[] args) {

		// Just going with the 'new session' use case
		boolean refresh = false;
		boolean startOver = true;

		// TODO: Put your own API key, secret, and callback URL here.
		String callbackUrl = ConfigLoad.get("CALLBACK_URI");

		String apiKey = ConfigLoad.get("CLIENT_ID");
		String apiSecret = ConfigLoad.get("CLIENT_SECRET");

		OAuthService service = new ServiceBuilder().provider(APIServer2.class)
				.apiKey(apiKey).apiSecret(apiSecret).callback(callbackUrl)
				.scope(SCOPE).offline(true).build();
		Scanner in = new Scanner(System.in);

		System.out.println("=== " + NETWORK_NAME + "'s OAuth Workflow ===");
		System.out.println();

		Verifier verifier = null;
		// TODO: Put your own token information here, if you don't want to start
		// over the whole process. This is necessary for the 'refresh-token'
		// flow.

		Token accessToken = new Token("ACCESS_TOKEN", "REFRESH_TOKEN");

		if (startOver) {
			// Obtain the Authorization URL
			System.out
					.println("==========================================================");
			System.out
					.println("1. Generating the Authorization URL with an empty token");
			String authorizationUrl = service.getAuthorizationUrl(EMPTY_TOKEN);
			System.out
					.println("==========================================================");
			System.out
					.println("2. Resource owner need to authorize the Client-App here:");
			System.out.println(authorizationUrl);

			System.out
					.println("2a. Paste the authorization code here, whenever ready");
			System.out.print(">>");
			verifier = new Verifier(in.nextLine());
			System.out.println();
			System.out
					.println("==========================================================");

			// Trade the Request Token and Verfier for the Access Token
			System.out
					.println("3. Trading the Authorization Request Token for an Access Token");
			accessToken = service.getAccessToken(EMPTY_TOKEN, verifier);
			System.out
					.println("3a. Server responded with the following details");
			System.out.println("\tAccess token : " + accessToken.getToken());
			// Default implementation on the Token class needs to be changed
			// System.out.println("\tExpires in   : " +
			// accessToken.getExpiry());
			System.out.println("\tRaw response : "
					+ accessToken.getRawResponse());
			System.out
					.println("==========================================================");
		}

		if (refresh) {
			try {
				// Trade the Refresh Token for a new Access Token
				System.out
						.println("==========================================================");
				System.out
						.println("1a. Trading the Refresh Token for a new Access Token");
				Token newAccessToken = service.getAccessToken(accessToken,
						verifier);
				System.out
						.println("1b. Server responded with the following details:\n "
								+ newAccessToken.getToken());
				System.out
						.println("==========================================================");
				accessToken = newAccessToken;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		// Now, next step is retreive the protected resource information - an
		// API secured by OAuth on API Server
		System.out
				.println("==========================================================");
		System.out
				.println("4. Building the OAuthRequest (with access_token) to access the protected resource");
		OAuthRequest request = new OAuthRequest(Verb.GET,
				PROTECTED_RESOURCE_URL);

		System.out
				.println("4a. Depending on how the access token needs to be \n"
						+ "used (header/query-string/post body), supply the 'Bearer' authorization with the token");
		request.addHeader("Authorization", "Bearer " + accessToken.getToken());
		System.out
				.println("==========================================================");
		System.out.println("5. Signing the OAuthRequest with the access token");
		service.signRequest(accessToken, request);
		System.out.println("5a. Submitted the 'signed' OAuthRequest");
		Response response = request.send();

		System.out
				.println("==========================================================");
		System.out
				.println("6. Reading the Response for the request on Step 5a.");
		System.out
				.println("*******************************************************************");
		System.out.println("Response Code: " + response.getCode());
		System.out.println("Response Body: " + response.getBody());

		System.out
				.println("*******************************************************************");
		System.out
				.println("==========================================================");

	}
}
