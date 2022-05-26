import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDTO } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { User } from '@prisma/client';

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

  async validateUser(username: string, password: string): Promise<User> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: username,
      },
    });

    if (!user) {
      return null;
    }

    const valid = await argon.verify(user.hash, password);
    if (!valid) {
      return null;
    }

    return user;
  }

  async signInLocal() {}

  async logout() {}

  async refreshTokens() {}
}
