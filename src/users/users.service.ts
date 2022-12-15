import { ConflictException, Injectable, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SignUpCredentialsDto } from 'src/authentication/dto/SignUpCredentials.dto';
import { SignInCredentialsDto } from 'src/authentication/dto/SignInCredentials.dto';
import { User as IUser } from './models/user.interface';
import { User } from './models/user.entity';
import { JwtPayload } from 'src/authentication/interfaces/jwt-payload.interface';

@Injectable()
export class UsersService {
  @InjectRepository(User)
  private readonly repository: Repository<User>;
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

  async validateUserPassword(signInCredentialsDto: SignInCredentialsDto): Promise<JwtPayload> {
    const { email, password } = signInCredentialsDto;
    const auth = await this.repository.findOne({ where: { email } });
    if (auth && (await auth.validatePassword(password, auth.password))) {
      return {
        isTwoFactorAuthenticationEnabled: auth.isTwoFactorAuthenticationEnabled,
        email: auth.email,
      };
    } else {
      return null;
    }
  }

  async update(email, hashedRefreshToken) {
    await this.repository.update({ email }, { hashedRefreshToken });
  }
}

/* 
async updateTodo(id: number, post: UpdateTodoDto) {
  await this.todoRepository.update(id, post);
  const updatedTodo = await this.todoRepository.findOne(id);
  if (updatedTodo) {
    return updatedTodo;
  }

  throw new HttpException('Todo not found', HttpStatus.NOT_FOUND);
}

======

async function update(id: string, user: User): Promise<User> {
    // Update
    await userRepository.update(id, {
      ...(user.name && { name: user.name }),
      ...(user.surname && { surname: user.surname }),
      ...(user.age && { age: user.age }),
    });

    // Return
    return this.repository.findOneOrFail(id);
  }

*/
