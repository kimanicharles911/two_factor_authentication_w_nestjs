import {
  Controller,
  HttpCode,
  Post,
  UseGuards,
  Request,
  Response,
  Body,
  UnauthorizedException,
  ValidationPipe,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { User } from '../users/models/user.interface';
import { LocalAuthGuard } from './local/local-auth.guard';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { UsersService } from '../users/users.service';
import { SignUpCredentialsDto } from './dto/SignUpCredentials.dto';
import { SignInCredentialsDto } from './dto/SignInCredentials.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Controller('auth')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService, private usersService: UsersService) {}

  @Post('/signup')
  async signUp(@Body(ValidationPipe) signUpCredentialsDto: SignUpCredentialsDto): Promise<{ message: string }> {
    return this.authenticationService.signUp(signUpCredentialsDto);
  }

  @Post('/signin')
  async signin(
    @Body(ValidationPipe) signInCredentialsDto: SignInCredentialsDto,
  ): Promise<{ accessToken: string; refreshToken?: string; user?: JwtPayload }> {
    return this.authenticationService.signIn(signInCredentialsDto);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(200)
  async login(@Request() req) {
    const userWithoutPsw: Partial<User> = req.user;

    return this.authenticationService.login(userWithoutPsw);
  }

  @Post('2fa/generate')
  @UseGuards(JwtAuthGuard)
  async register(@Response() response, @Request() request) {
    const { otpAuthUrl } = await this.authenticationService.generateTwoFactorAuthenticationSecret(request.user);
    return response.json(await this.authenticationService.generateQrCodeDataURL(otpAuthUrl));
  }

  @Post('2fa/turn-on')
  @UseGuards(JwtAuthGuard)
  async turnOnTwoFactorAuthentication(@Request() request, @Body() body) {
    const isCodeValid = this.authenticationService.isTwoFactorAuthenticationCodeValid(
      body.twoFactorAuthenticationCode,
      request.user,
    );
    if (!isCodeValid) {
      throw new UnauthorizedException('Wrong authentication code');
    }
    return await this.usersService.turnOnTwoFactorAuthentication(request.user.id);
  }

  @Post('2fa/turn-off')
  @UseGuards(JwtAuthGuard)
  async turnOffTwoFactorAuthentication(@Request() request, @Body() body) {
    const isCodeValid = this.authenticationService.isTwoFactorAuthenticationCodeValid(
      body.twoFactorAuthenticationCode,
      request.user,
    );
    if (!isCodeValid) {
      throw new UnauthorizedException('Wrong authentication code');
    }
    return await this.usersService.turnOffTwoFactorAuthentication(request.user.id);
  }

  @Post('2fa/authenticate')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async authenticate(@Request() request, @Body() body) {
    console.log(` body.twoFactorAuthenticationCode / `, body.twoFactorAuthenticationCode);
    console.log(`request.user / `, request.user);
    const isCodeValid = this.authenticationService.isTwoFactorAuthenticationCodeValid(
      body.twoFactorAuthenticationCode,
      request.user,
    );
    console.log(`isCodeValid / `, isCodeValid);
    if (!isCodeValid) {
      throw new UnauthorizedException('Wrong authentication code');
    }
    return this.authenticationService.loginWith2fa(request.user);
  }
}
