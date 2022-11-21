package com.encore.petandbe.infrastructure.oauth;

import java.io.IOException;
import java.util.Map;

public interface OAuthManager {
	Map<String, String> convertAuthorizationCodeToInfo(String authorizationCode) throws
		IOException,
		InterruptedException;
}

