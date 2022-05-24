import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDTO } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signUpLocal(dto: CreateUserDTO): Promise<Tokens> {
    const hash = await argon.hash(dto.password);
    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        hash,
      },
    });

    return {
      accessToken: user.hash,
      refreshToken: user.hash,
    };
  }

  async signInLocal() {}

  async logout() {}

  async refreshTokens() {}
}
