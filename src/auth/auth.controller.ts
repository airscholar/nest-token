import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDTO } from './dto';
import { AuthDTO } from './dto/auth.dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async signUpLocal(@Body() dto: CreateUserDTO): Promise<Tokens> {
    return await this.authService.signUpLocal(dto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async signInLocal(@Body() dto: AuthDTO) {
    return await this.authService.signInLocal(dto);
  }

  @Post('logout')
  async logout() {
    // return await this.authService.logout();
  }

  @Post('refresh')
  async refreshTokens() {
    return await this.authService.refreshTokens();
  }
}
