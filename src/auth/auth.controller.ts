import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDTO } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  async signUpLocal(@Body() dto: CreateUserDTO): Promise<Tokens> {
    return await this.authService.signUpLocal(dto);
  }

  @Post('local/signin')
  async signInLocal() {
    return await this.authService.signInLocal();
  }

  @Post('logout')
  async logout() {
    return await this.authService.logout();
  }

  @Post('refresh')
  async refreshTokens() {
    return await this.authService.refreshTokens();
  }
}
