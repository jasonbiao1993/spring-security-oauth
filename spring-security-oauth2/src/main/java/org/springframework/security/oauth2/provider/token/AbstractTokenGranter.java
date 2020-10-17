/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.token;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Dave Syer
 * 
 */
@Deprecated
public abstract class AbstractTokenGranter implements TokenGranter {
	
	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * 与token相关的service，重点
	 */
	private final AuthorizationServerTokenServices tokenServices;

	/**
	 * 与clientDetails相关的service，重点
	 */
	private final ClientDetailsService clientDetailsService;

	/**
	 * 创建oauth2Request的工厂，重点
	 */
	private final OAuth2RequestFactory requestFactory;
	
	private final String grantType;

	protected AbstractTokenGranter(AuthorizationServerTokenServices tokenServices,
			ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
		this.clientDetailsService = clientDetailsService;
		this.grantType = grantType;
		this.tokenServices = tokenServices;
		this.requestFactory = requestFactory;
	}

	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {

		// 1、 判断 grantType 是否匹配
		if (!this.grantType.equals(grantType)) {
			return null;
		}

		// 2、 获取  ClientDetails 信息 并验证 grantType
		String clientId = tokenRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);

		if (logger.isDebugEnabled()) {
			logger.debug("Getting access token for: " + clientId);
		}

		// 3、 调用 getAccessToken() 方法生成token并返回
		return getAccessToken(client, tokenRequest);

	}

	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		// 通过token服务，保存token对象
		return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
	}

	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(client, tokenRequest);
		return new OAuth2Authentication(storedOAuth2Request, null);
	}

	protected void validateGrantType(String grantType, ClientDetails clientDetails) {
		Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidClientException("Unauthorized grant type: " + grantType);
		}
	}

	protected AuthorizationServerTokenServices getTokenServices() {
		return tokenServices;
	}
	
	protected OAuth2RequestFactory getRequestFactory() {
		return requestFactory;
	}

}
