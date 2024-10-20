interface Env {
	JAMBOS_KV: KVNamespace
}

function formatError(error: string) {
	const obj = {"error": error}
	return JSON.stringify(obj)
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL (request.url)
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

		if (path === "/list") {
			const list = await env.JAMBOS_KV.list()
			if (list === null) {
				return new Response("Failed kv fetch", { status: 404 })
			}
			return new Response(JSON.stringify(list.keys), { status: 200})
		}
		return new Response("Invalid api request", { status: 404 })
	},
} satisfies ExportedHandler<Env>;