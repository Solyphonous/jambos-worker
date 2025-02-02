import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

interface Env {
	JAMBOS_KV: KVNamespace;
	DB: D1Database;
	WorkersAPIKey: string;
	JWTSigningKey: string;
}

type User = {
	id: number;
	username: string;
	hashpass: string;
	rank: number;
};

function formatMessage(item: string, value: any) {
	return JSON.stringify({ [item]: value });
}

function formatError(error: string) {
	return formatMessage('error', error);
}

async function hashPassword(password: string): Promise<string> {
	bcrypt.genSalt(10, function (err, salt) {
		bcrypt.hash(password, salt, function (err, hash) {
			return hash;
		});
	});
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const WorkersAPIKey = env.WorkersAPIKey;
		const JWTSigningKey = env.JWTSigningKey;

		const apiKey = request.headers.get('Authorization');
		if (apiKey !== WorkersAPIKey) {
			return new Response(formatError('Invalid API key!'), { status: 403 });
		}

		// Request article
		const url = new URL(request.url);
		const path = url.pathname.replace(/^\/api/, '');
		const articlepath = /^\/article\/(.*)$/.exec(path);

		if (articlepath) {
			const articleName = articlepath[1].replace(/-/g, ' ');
			var article = await env.JAMBOS_KV.get(articleName);

			if (article) {
				var articleJSON = JSON.parse(article);
				articleJSON.name = articleName;

				return new Response(JSON.stringify(articleJSON), {
					status: 200,
					headers: {
						'Content-Type': 'application/json',
					},
				});
			} else {
				return new Response(formatError('Article not found!'), { status: 404 });
			}
		}

		// Upload article
		if (path === '/upload_article') {
			const body = await request.json();
			const { article, token } = body;

			try {
				const verifiedToken = jwt.verify(token, JWTSigningKey, { algorithm: 'HS256' });

				try {
					if (verifiedToken.rank > 250) {
						article.author = verifiedToken.username;
						await env.JAMBOS_KV.put(String(Date.now()), JSON.stringify(article));
					}
				} catch (err) {
					return new Response(formatError(err), { status: 404 });
				}

				return new Response(formatMessage('Message', 'Success!'), { status: 200 });
			} catch {
				return new Response(formatError('Invalid token'), { status: 404 });
			}
		}

		// Request news list

		if (path === '/list') {
			const list = await env.JAMBOS_KV.list();
			if (list === null) {
				return new Response(formatError('Failed KV fetch'), { status: 500 });
			}

			const reversed = list.keys.reverse();
			return new Response(JSON.stringify(reversed), { status: 200 });
		}

		// Login

		if (path === '/login') {
			const body = await request.json();
			const { username, password } = body;

			const result = await env.DB.prepare('SELECT * FROM Users WHERE username = ?').bind(username).first<User>();

			if (!result) {
				return new Response(formatError('User does not exist!'), { status: 404 });
			}

			const isMatch = await bcrypt.compare(password, result.hashpass);

			if (!isMatch) {
				return new Response(formatError('Incorrect password!'), { status: 400 });
			}

			var token = jwt.sign(
				{
					id: result.id,
					username: result.username,
					rank: result.rank,
				},
				JWTSigningKey,
				{ algorithm: 'HS256' },
			);

			return new Response(formatMessage('token', token), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		}

		// Sign up

		if (path == '/signup') {
			const body = await request.json();
			const { username, password } = body;

			const userExists = await env.DB.prepare('SELECT * FROM Users WHERE username = ?').bind(username).first<User>();

			if (userExists) {
				return new Response(formatError('User already exists!'), { status: 400 });
			}

			const salt = await bcrypt.genSalt(10);
			const hash: string = await bcrypt.hash(password, salt);

			const addUser = await env.DB.prepare('INSERT INTO Users (username, hashpass, rank) VALUES (?, ?, ?)').bind(username, hash, 1).run();

			if (addUser.success) {
				return new Response(formatMessage('message', 'Account successfully created.'), { status: 201 });
			} else {
				return new Response(formatError('Account failed to create.'), { status: 400 });
			}
		}

		if (path == '/verifytoken') {
			const body = await request.json();
			const { token } = body;

			try {
				const verifiedToken = jwt.verify(token, JWTSigningKey, { algorithm: 'HS256' });
				return new Response(formatMessage('token', verifiedToken), { status: 200 });
			} catch {
				return new Response(formatError('Invalid token'), { status: 404 });
			}
		}

		return new Response(formatError('Invalid api request'), { status: 404 });
	},
} satisfies ExportedHandler<Env>;
