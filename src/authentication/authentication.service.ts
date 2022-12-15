import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { User } from '../users/models/user.interface';
import { JwtService } from '@nestjs/jwt';
import { authenticator } from 'otplib';
import { toDataURL } from 'qrcode';
import { SignUpCredentialsDto } from './dto/SignUpCredentials.dto';
import { SignInCredentialsDto } from './dto/SignInCredentials.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthenticationService {
  constructor(private usersService: UsersService, private jwtService: JwtService) {}

  async signUp(signUpCredentialsDto: SignUpCredentialsDto): Promise<{ message: string }> {
    return this.usersService.signUp(signUpCredentialsDto);
  }

  async getAccessToken(payload: JwtPayload) {
    const accessToken = await this.jwtService.sign(payload, {
      secret: 'secret',
      expiresIn: '1d',
    });
    return accessToken;
  }

  async getRefreshToken(payload: JwtPayload) {
    const refreshToken = await this.jwtService.sign(payload, {
      secret: 'refresh_secret',
      expiresIn: '1d',
    });
    return refreshToken;
  }

  async updateRefreshTokenInUser(refreshToken, email) {
    if (refreshToken) {
      refreshToken = await bcrypt.hash(refreshToken, 10);
    }
    /* await this.usersService.update(
      { email },
      {
        hashedRefreshToken: refreshToken,
      },
    ); */
    await this.usersService.update(email, refreshToken);
  }

  async signIn(
    signInCredentialsDto: SignInCredentialsDto,
  ): Promise<{ accessToken: string; refreshToken?: string; user?: JwtPayload }> {
    const response = await this.usersService.validateUserPassword(signInCredentialsDto);
    if (!response) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const accessToken = await this.getAccessToken(response);
    if (response.isTwoFactorAuthenticationEnabled) {
      return {
        accessToken,
      };
    }

    const refreshToken = await this.getRefreshToken(response);
    await this.updateRefreshTokenInUser(refreshToken, response.email);
    return {
      accessToken,
      refreshToken,
      user: response,
    };
  }

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
    await this.usersService.setTwoFactorAuthenticationSecret(secret, user.id);
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
