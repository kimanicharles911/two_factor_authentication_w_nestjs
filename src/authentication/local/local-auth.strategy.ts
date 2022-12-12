import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthenticationService } from '../authentication.service';
import { User } from '../../users/models/user.interface';

@Injectable()
export class LocalAuthStrategy extends PassportStrategy(Strategy) {
  constructor(private authenticationService: AuthenticationService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string): Promise<Partial<User>> {
    const userWithoutPassword = await this.authenticationService.validateUser(email, password);
    console.log(`userWithoutPassword / `, userWithoutPassword);
    if (!userWithoutPassword) throw new UnauthorizedException();
    return userWithoutPassword;
  }
}
