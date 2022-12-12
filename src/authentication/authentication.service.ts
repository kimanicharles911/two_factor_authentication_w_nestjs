import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { User } from '../users/models/user.interface';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';

@Injectable()
export class AuthenticationService {
  constructor(private usersService: UsersService, private jwtService: JwtService) {}

  async validateUser(email: string, password: string): Promise<Partial<User>> {
    const user = await this.usersService.findOne(email);
    try {
      const isMatch = password === user.password;
      if (user && isMatch) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
      }
    } catch (error) {
      return null;
    }
  }

  async login(userWithoutPassword: Partial<User>) {
    const payload = {
      email: userWithoutPassword.email,
    };
    return {
      email: payload.email,
      access_token: this.jwtService.sign(payload),
    };
  }

  async generateTwoFactorAuthenticationSecret(user: User) {
    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, 'AUTH_APP_NAME', secret);
    await this.usersService.setTwoFactorAuthenticationSecret(secret, user.userId);
    return { secret, otpAuthUrl };
  }

  async generateQrCodeDataURL(otpAuthUrl: string) {
    return toDataURL(otpAuthUrl);
  }

  isTwoFactorAuthenticationCodeValid(twoFactorAuthenticationCode: string, user: User) {
    console.log(`twoFactorAuthenticationCode / `, twoFactorAuthenticationCode);
    console.log(`user / `, user);
    return authenticator.verify({
      token: twoFactorAuthenticationCode,
      secret: user.twoFactorAuthenticationSecret,
    });
  }

  async loginWith2fa(userWithoutPassword: Partial<User>) {
    const payload = {
      email: userWithoutPassword.email,
      isTwoFactorAuthenticationEnabled: !!userWithoutPassword.isTwoFactorAuthenticationEnabled,
      isTwoFactorAuthenticated: true,
    };
    return {
      email: payload.email,
      access_token: this.jwtService.sign(payload),
    };
  }
}
