import { Injectable } from '@nestjs/common';
import { User } from './models/user.interface';

@Injectable()
export class UsersService {
  private readonly users = [
    {
      userId: 1,
      email: 'john@test.com',
      username: 'john',
      password: 'password',
      twoFactorAuthenticationSecret: 'secret',
      isTwoFactorAuthenticationEnabled: false,
    },
    {
      userId: 2,
      email: 'maria@test.com',
      username: 'maria',
      password: 'password',
      twoFactorAuthenticationSecret: 'secret',
      isTwoFactorAuthenticationEnabled: false,
    },
  ];

  async findOne(email: string): Promise<User | undefined> {
    return this.users.find((user) => user.email === email);
  }

  async setTwoFactorAuthenticationSecret(secret: string, userId: number) {
    this.users.find((user) => user.userId === userId).twoFactorAuthenticationSecret = secret;
  }

  async turnOnTwoFactorAuthentication(userId: number) {
    this.users.find((user) => user.userId === userId).isTwoFactorAuthenticationEnabled = true;
  }
}
