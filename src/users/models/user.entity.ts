import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { Exclude } from 'class-transformer';

@Entity('users_test')
export class User extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar' })
  email: string;

  @Column({ type: 'varchar', nullable: true })
  first_name: string;

  @Column({ type: 'varchar', nullable: true })
  last_name: string;

  @Column({ type: 'numeric', nullable: true })
  phone_number: number;

  @Column({ type: 'varchar' })
  password: string;

  @Column()
  salt: string;

  @Column({ nullable: true })
  @Exclude()
  public hashedRefreshToken?: string;

  @Column({ nullable: true })
  twoFactorAuthenticationSecret?: string;

  @Column({ type: 'boolean', default: false })
  public isTwoFactorAuthenticationEnabled: boolean;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  async validatePassword(password: string, hashedPassword: string): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword).then((result) => result);
  }
}
