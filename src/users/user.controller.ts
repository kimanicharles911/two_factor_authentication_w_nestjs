import { Body, Controller, Param, Patch, UseGuards } from '@nestjs/common';
import { Observable } from 'rxjs';
import { UpdateResult } from 'typeorm';
import { Jwt2faAuthGuard } from '../authentication/jwt-2fa/jwt-2fa-auth.guard';
import { User as IUser } from './models/user.interface';
import { UsersService } from './users.service';

@Controller('user')
@UseGuards(Jwt2faAuthGuard)
export class UserController {
  constructor(private usersService: UsersService) {}

  @Patch(':id')
  updateUserProfile(@Param('id') id: number, @Body() user: Partial<IUser>): Observable<UpdateResult> {
    return this.usersService.updateUserProfile(id, user);
  }
}
