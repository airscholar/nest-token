import { AuthGuard } from '@nestjs/passport';

export class JWTRTGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
