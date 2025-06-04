import { BaseOAuthProvider } from './oauth-provider.baseclass';
import { GoogleOAuthProvider } from './google-oauth.provider';
import { BadRequestDomainException } from '../../../../../core/exceptions/domain-exceptions';
import { HttpHelper } from './oauth-http-req.helper';
import { UserConfig } from '../../../config/user.config';

export enum OAuthProviderType {
  Google = 'google',
  GitHub = 'github',
  Facebook = 'facebook',
}

const providersMap = {
  [OAuthProviderType.Google]: GoogleOAuthProvider,
  //[OAuthProviderType.GitHub]: GitHubOAuthProvider,
  //[OAuthProviderType.Facebook]: FacebookOAuthProvider,
};

export function OAuthProviderFactory(
  providerType: OAuthProviderType,
  httpHelper: HttpHelper,
  userConfig: UserConfig,
): BaseOAuthProvider {
  const ProviderClass = providersMap[providerType];
  if (!ProviderClass) {
    throw BadRequestDomainException.create(
      `Unsupported OAuth provider: ${providerType}`,
    );
  }
  return new ProviderClass(httpHelper, userConfig);
}
