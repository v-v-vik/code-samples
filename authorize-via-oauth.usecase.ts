import { SessionData } from '../../guards/decorators/user-ip-agent-from-req.decorator';
import { CommandBus, CommandHandler, ICommandHandler } from '@nestjs/cqrs';
import { UsersRepository } from '../../infrastructure/users.repository';
import { LoginCommand } from '../useCases/authUseCases/login.usecase';
import { HttpHelper } from './providers/oauth-http-req.helper';
import { UserConfig } from '../../config/user.config';
import {
  OAuthProviderFactory,
  OAuthProviderType,
} from './providers/oauth-provider-factory.service';
import { BaseOAuthProvider } from './providers/oauth-provider.baseclass';
import { User } from '../../domain/user.entity';
import { accessAndRefreshTokenDto } from '../../api/dto/auth-dto';

export type OAuthUserData = {
  email: string;
  oAuthId: string;
};

export class AuthorizeViaOAuthCommand {
  constructor(
    public sessionData: SessionData,
    public provider: OAuthProviderType,
    public code: string,
  ) {}
}

@CommandHandler(AuthorizeViaOAuthCommand)
export class AuthorizeViaOAuthUseCase
  implements ICommandHandler<AuthorizeViaOAuthCommand>
{
  constructor(
    private commandBus: CommandBus,
    private usersRepository: UsersRepository,
    private userConfig: UserConfig,
    private httpHelper: HttpHelper,
  ) {}

  async execute(
    command: AuthorizeViaOAuthCommand,
  ): Promise<accessAndRefreshTokenDto> {
    const { sessionData, provider, code } = command;
    const oauthProvider: BaseOAuthProvider = OAuthProviderFactory(
      provider,
      this.httpHelper,
      this.userConfig,
    );
    const oauthUserData: OAuthUserData = await oauthProvider.getOAuthUser(code);
    const foundUser = await this.usersRepository.findByEmail(
      oauthUserData.email,
    );
    if (foundUser) {
      foundUser.updateOAuthId(provider, oauthUserData.oAuthId);
      await this.usersRepository.save(foundUser);
      return await this.commandBus.execute(
        new LoginCommand(foundUser.id, sessionData.agent, sessionData.ip),
      );
    }
    const newUser: User = await this.commandBus.execute(
      new CreateNewUserViaOAuthCommand(
        provider,
        oauthUserData.email,
        oauthUserData.oAuthId,
      ),
    );
    return await this.commandBus.execute(
      new LoginCommand(newUser.id, sessionData.agent, sessionData.ip),
    );
  }
}
