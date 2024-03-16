import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
        console.log(user.rows[0])
        return user.rows[0];

    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
    // if (email === 'user@nextmail.com') {
    //     return {
    //         id: '410544b2-4001-4271-9855-fec4b6a6442a',
    //         name: 'User',
    //         email: 'user@nextmail.com',
    //         password: '123456',
    //     }
    // } else {
    //     console.error('Failed to fetch user:', email);
    //     throw new Error('Failed to fetch user.');
    // }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
        Credentials({
            async authorize(credentials) {
                const parsedCredentials = z
                    .object({ email: z.string().email(), password: z.string().min(3) })
                    .safeParse(credentials);
                    console.log(parsedCredentials.success);
                if (parsedCredentials.success) {
                    const { email, password } = parsedCredentials.data;
                    const user = await getUser(email);
                    if (!user) return null;
                    const passwordsMatch = await bcrypt.compare(password, user.password);
                    // console.log(password, user.password);
                    // console.log(user);
                    // if (password === user.password) return user;
                    if (passwordsMatch) return user;
                }

                console.log('Invalid credentials');
                return null;
            },
        }),
    ],
});