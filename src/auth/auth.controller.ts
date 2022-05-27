import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDTO } from './dto';
import { AuthDTO } from './dto/auth.dto';
import { JWTRTGuard } from '../common/guards';
import { JWTGuard } from '../common/guards/jwt-at.guard';
import { Tokens } from '../common/types';
import { GetUser, Public } from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async signUpLocal(@Body() dto: CreateUserDTO): Promise<Tokens> {
    return await this.authService.signUpLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async signInLocal(@Body() dto: AuthDTO) {
    return await this.authService.signInLocal(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@GetUser('sub') userId: number) {
    return await this.authService.logout(userId);
  }

  @UseGuards(JWTRTGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@GetUser() user: any) {
    return await this.authService.refreshTokens(
      user['sub'],
      user['refreshToken'],
    );
  }
}
