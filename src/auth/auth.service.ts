import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateUserDTO } from './dto';
import * as argon from 'argon2';
import { Tokens } from './types';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { AuthDTO } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signUpLocal(dto: CreateUserDTO): Promise<Tokens> {
    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        hash: await this.hashData(dto.password),
      },
    });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRTHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async signInLocal(authDTO: AuthDTO): Promise<Tokens> {
    const user = await this.validateUser(authDTO.email, authDTO.password);

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRTHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRT: {
          not: null,
        },
      },
      data: {
        hashedRT: null,
      },
    });
  }

  async refreshTokens() {}

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

  async updateRTHash(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user) throw new NotFoundException('User not found');

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        hashedRT: await this.hashData(rt),
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        { secret: 'AT-secret', expiresIn: 60 * 15 }, // 15 minutes
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        { secret: 'RT-secret', expiresIn: 60 * 60 * 24 * 7 }, // 7 days
      ),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
    };
  }

  async hashData(data: string): Promise<string> {
    return await argon.hash(data);
  }
}
