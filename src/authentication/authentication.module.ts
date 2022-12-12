import { Module } from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { AuthenticationController } from './authentication.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { LocalAuthStrategy } from './local/local-auth.strategy';
import { JwtStrategy } from './jwt/jwt.strategy';
import { Jwt2faStrategy } from './jwt-2fa/jwt-2fa.strategy';

@Module({
  imports: [
    UsersModule,
    JwtModule.register({
      secret: 'secret',
      signOptions: { expiresIn: '1d' },
    }),
  ],
  controllers: [AuthenticationController],
  providers: [AuthenticationService, LocalAuthStrategy, JwtStrategy, Jwt2faStrategy],
})
export class AuthenticationModule {}
