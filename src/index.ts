import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

interface Env {
	JAMBOS_KV: KVNamespace;
	DB: D1Database;
	WorkersAPIKey: string;
	JWTSigningKey: string;
}

type User = {
	userId: number;
	username: string;
	hashpass: string;
	rank: number;
};

// Helper functions

const jsonResponse = (data: object, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});

const errorResponse = (message: string, status = 400) => jsonResponse({ error: message }, status);

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const WorkersAPIKey = env.WorkersAPIKey;
		const JWTSigningKey = env.JWTSigningKey;

		const apiKey = request.headers.get('Authorization');
		if (apiKey !== WorkersAPIKey) {
			return errorResponse('Invalid API key!', 403);
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

				return jsonResponse(articleJSON);
			} else {
				return errorResponse('Article not found!', 404);
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
					return errorResponse(err);
				}

				return jsonResponse({ message: 'Success!' });
			} catch {
				return errorResponse('Invalid token!');
			}
		}

		// Request news list

		if (path === '/list') {
			const list = await env.JAMBOS_KV.list();
			if (list === null) {
				return errorResponse('Failed KV fetch!', 500);
			}

			return jsonResponse(list.keys.reverse());
		}

		// Login

		if (path === '/login') {
			const body = await request.json();
			const { username, password } = body;

			const result = await env.DB.prepare('SELECT * FROM Users WHERE username = ?').bind(username).first<User>();

			if (!result) {
				return errorResponse('User does not exist!', 404);
			}

			const isMatch = await bcrypt.compare(password, result.hashpass);

			if (!isMatch) {
				return errorResponse('Invalid password!');
			}

			var token = jwt.sign(
				{
					userId: result.userId,
					username: result.username,
					rank: result.rank,
				},
				JWTSigningKey,
				{ algorithm: 'HS256' },
			);

			return jsonResponse({ token: token });
		}

		// Sign up

		if (path === '/signup') {
			const body = await request.json();
			const { username, password } = body;

			const userExists = await env.DB.prepare('SELECT * FROM Users WHERE username = ?').bind(username).first<User>();

			if (userExists) {
				return errorResponse('User already exists!');
			}

			const salt = await bcrypt.genSalt(10);
			const hash: string = await bcrypt.hash(password, salt);

			const addUser = await env.DB.prepare('INSERT INTO Users (username, hashpass, rank) VALUES (?, ?, ?)').bind(username, hash, 1).run();

			if (addUser.success) {
				return jsonResponse({ message: 'Account created successfully!' }, 201);
			} else {
				return errorResponse('Account failed to create.');
			}
		}

		// Create comment

		if (path === '/comment') {
			const body = await request.json();
			const { article, comment, token } = body;

			try {
				const verifiedToken = jwt.verify(token, JWTSigningKey, { algorithm: 'HS256' });

				try {
					if (verifiedToken) {
						const createComment = await env.DB.prepare('INSERT INTO Comments (articleId, posterId, content) VALUES (?, ?, ?)')
							.bind(article, verifiedToken.userId, comment)
							.run();
					}
				} catch (err) {
					return errorResponse(err);
				}

				return jsonResponse({ message: 'Success!' });
			} catch {
				return errorResponse('Invalid token!');
			}
		}

		// Get comments

		if (path == '/get_comments') {
			const body = await request.json();
			const { article } = body;

			try {
				const comments = await env.DB.prepare(
					`
					SELECT c.commentId, c.content, c.createdAt, u.username
					FROM Comments c
					JOIN Users u ON c.posterId=u.userId
					WHERE c.articleId = ?
					ORDER BY c.createdAt DESC
					`,
				)
					.bind(article)
					.all();

				return jsonResponse(comments.results);
			} catch {
				return errorResponse('Failed to fetch comments!');
			}
		}

		// Verify token

		if (path === '/verifytoken') {
			const body = await request.json();
			const { token } = body;

			try {
				const verifiedToken = jwt.verify(token, JWTSigningKey, { algorithm: 'HS256' });
				return jsonResponse({ token: verifiedToken });
			} catch {
				return errorResponse('Invalid token!');
			}
		}

		return errorResponse('Invalid API request!');
	},
} satisfies ExportedHandler<Env>;
