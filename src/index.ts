import jsonwebtoken from "jsonwebtoken"
import bcrypt from "bcryptjs"

interface Env {
	JAMBOS_KV: KVNamespace,
	DB: D1Database,
	WorkersAPIKey: string,
	JWTSigningKey: string
}

type User = {
	id: number,
	username: string,
	hashpass: string,
	rank: number
}

function formatError(error: string) {
	const obj = { "error": error }
	return JSON.stringify(obj)
}

async function hashPassword(password: string): Promise<string> {
	bcrypt.genSalt(10, function (err, salt) {
		bcrypt.hash(password, salt, function (err, hash) {
			return hash
		})
	})
}

export default {
	async fetch(request, env, ctx): Promise<Response> {

		const WorkersAPIKey = env.WorkersAPIKey
		const JWTSigningKey = env.JWTSigningKey

		const apiKey = request.headers.get("Authorization")
		if (apiKey !== WorkersAPIKey) {
			return new Response(formatError("Invalid API key!"), { status: 404 })
		}

		// Request article
		const url = new URL(request.url)
		const path = url.pathname.replace(/^\/api/, "")
		const articlepath = /^\/article\/(.*)$/.exec(path)

		if (articlepath) {
			const articleName = articlepath[1].replace(/-/g, " ")
			const article = await env.JAMBOS_KV.get(articleName)

			if (article) {
				return new Response(article, {
					status: 200,
					headers: {
						"Content-Type": "application/json"
					}
				})
			}
			else {
				return new Response(formatError("Article not found!"), { status: 404 })
			}
		}

		// Request news list

		if (path === "/list") {
			const list = await env.JAMBOS_KV.list()
			if (list === null) {
				return new Response(formatError("Failed KV fetch"), { status: 404 })
			}
			return new Response(JSON.stringify(list.keys), { status: 200 })
		}

		// Login

		if (path === "/login") {
			const body = await request.json()
			const { username, password } = body

			const result = await env.DB
				.prepare("SELECT * FROM Users WHERE username = ?")
				.bind(username)
				.first<User>()

			if (!result) {
				return new Response(formatError("User does not exist!"), { status: 404 })
			}

			const isMatch = await bcrypt.compare(password, result.hashpass)

			if (!isMatch) {
				return new Response(formatError("Incorrect password!"), { status: 404 })
			}

			var token = jsonwebtoken.sign(
				{
					id: result.id,
					username: result.username,
					rank: result.rank
				},
				JWTSigningKey,
				{ algorithm: "HS256" }
			)

			return new Response(JSON.stringify(token), {
				status: 200,
				headers: { "Content-Type": "application/json" }
			})
		}

		// Sign up

		if (path == "/signup") {
			const body = await request.json()
			const { username, password } = body

			const result = await env.DB
				.prepare("SELECT * FROM Users WHERE username = ?")
				.bind(username)
				.first<User>()

			if (result) {
				return new Response(formatError("User already exists!"), { status: 404 })
			}

			const salt = await bcrypt.genSalt(10)
			const hash: string = await bcrypt.hash(password, salt);

			env.DB
			.prepare("INSERT INTO Users (username, hashpass, rank) VALUES (?, ?, ?)")
			.bind(username, hash, 1)
			.run()

		}

		return new Response(formatError("Invalid api request"), { status: 404 })
	},
} satisfies ExportedHandler<Env>;