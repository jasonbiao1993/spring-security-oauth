/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Interface for granters of access tokens. Various grant types are defined in the specification, and each of those has
 * an implementation, leaving room for extensions to the specification as needed.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Dave Syer
 *
 * TokenGranter的设计思路是使用CompositeTokenGranter管理一个List列表，每一种grantType对应一个具体的真正授权者
 *
 * ResourceOwnerPasswordTokenGranter ==> password密码模式
 * AuthorizationCodeTokenGranter ==> authorization_code授权码模式
 * ClientCredentialsTokenGranter ==> client_credentials客户端模式
 * ImplicitTokenGranter ==> implicit简化模式
 * RefreshTokenGranter ==>refresh_token 刷新token专用
 *
 * 通过扩展实现自定义授权模式
 */
@Deprecated
public interface TokenGranter {

	OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest);

}
