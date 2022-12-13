import { ConflictException, Injectable, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { SignUpCredentialsDto } from 'src/authentication/dto/SignUpCredentials.dto';
import { User as IUser } from './models/user.interface';
import { User } from './models/user.entity';

@Injectable()
export class UsersService {
  private readonly users = [
    {
      id: 1,
      email: 'john@test.com',
      username: 'john',
      password: 'password',
      twoFactorAuthenticationSecret: 'secret',
      isTwoFactorAuthenticationEnabled: false,
    },
    {
      id: 2,
      email: 'maria@test.com',
      username: 'maria',
      password: 'password',
      twoFactorAuthenticationSecret: 'secret',
      isTwoFactorAuthenticationEnabled: false,
    },
  ];

  private async hashPassword(password: string, salt: string): Promise<string> {
    return bcrypt.hash(password, salt);
  }

  async findOne(email: string): Promise<IUser | undefined> {
    return this.users.find((user) => user.email === email);
  }

  async setTwoFactorAuthenticationSecret(secret: string, id: number) {
    this.users.find((user) => user.id === id).twoFactorAuthenticationSecret = secret;
  }

  async turnOnTwoFactorAuthentication(id: number) {
    this.users.find((user) => user.id === id).isTwoFactorAuthenticationEnabled = true;
  }

  async signUp(signUpCredentialsDto: SignUpCredentialsDto): Promise<{ message: string }> {
    const { email, password } = signUpCredentialsDto;
    const user = new User();
    user.email = email;
    user.salt = await bcrypt.genSalt();
    user.password = await this.hashPassword(password, user.salt);
    try {
      await user.save();
      return { message: 'User successfully created!' };
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('Username already exists');
      } else {
        throw new InternalServerErrorException();
      }
    }
  }
}
