import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  signin() {
    return { msg: 'this is signin' };
  }
  signup() {
    return { msg: 'this is signup' };
  }
}
