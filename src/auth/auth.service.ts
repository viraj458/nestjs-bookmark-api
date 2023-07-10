import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { Prisma } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    try {
      //generate passwod hash
      const hash = await argon.hash(dto.password);

      //save user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      //return token
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('credential exception');
        }
      }
      throw error;
    }
  }
  async signin(dto: AuthDto) {
    //find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    //if not user throw exception
    if (!user) throw new ForbiddenException('credentials incorrect');

    //compare password
    const pwCheck = await argon.verify(user.hash, dto.password);

    //if password incorrect throw error
    if (!pwCheck) throw new ForbiddenException('wrong password');

    ///return token
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '3d',
      secret: secret,
    });
    return {
      access_token: token,
    };
  }
}
