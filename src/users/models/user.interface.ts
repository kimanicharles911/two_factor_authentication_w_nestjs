export interface User {
  id: number;
  email: string;
  username: string;
  password: string;
  twoFactorAuthenticationSecret: string;
  isTwoFactorAuthenticationEnabled: boolean;
}
