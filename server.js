const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { randomUUID } = require("node:crypto");
const { Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const {
	S3Client,
	PutObjectCommand,
	GetObjectCommand,
	HeadObjectCommand,
	ListObjectsV2Command
} = require("@aws-sdk/client-s3");

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(ROOT, "uploads"));
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024;
const FRONTEND_ORIGINS = new Set(
	(process.env.FRONTEND_ORIGINS || "")
		.split(",")
		.map(origin => origin.trim())
		.filter(Boolean)
);
const R2_KEYS = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME"];
const configuredR2Keys = R2_KEYS.filter(key => process.env[key]);
if (configuredR2Keys.length > 0 && configuredR2Keys.length !== R2_KEYS.length) {
	throw new Error(`Set all Cloudflare R2 environment variables: ${R2_KEYS.join(", ")}.`);
}
if (process.env.RENDER && configuredR2Keys.length === 0) {
	throw new Error(`Cloudflare R2 must be configured on Render. Set: ${R2_KEYS.join(", ")}.`);
}
const r2Bucket = process.env.R2_BUCKET_NAME;
const r2 = configuredR2Keys.length === R2_KEYS.length
	? new S3Client({
		region: "auto",
		endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
		credentials: {
			accessKeyId: process.env.R2_ACCESS_KEY_ID,
			secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
		}
	})
	: null;
const VIDEO_TYPES = {
	"video/mp4": "mp4",
	"video/webm": "webm",
	"video/quicktime": "mov",
	"video/x-matroska": "mkv"
};
const STATIC_TYPES = {
	".css": "text/css; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".ico": "image/x-icon",
	".jpeg": "image/jpeg",
	".jpg": "image/jpeg",
	".js": "text/javascript; charset=utf-8",
	".png": "image/png",
	".svg": "image/svg+xml",
	".webp": "image/webp"
};

function sendJson(res, status, data) {
	res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
	res.end(JSON.stringify(data));
}

function handleCors(req, res) {
	const origin = req.headers.origin;
	if (!origin) return true;

	let sameOrigin = false;
	try {
		sameOrigin = new URL(origin).host === req.headers.host;
	} catch {
		sameOrigin = false;
	}

	if (!sameOrigin && !FRONTEND_ORIGINS.has(origin)) {
		sendJson(res, 403, { error: "This website is not allowed to use the API." });
		return false;
	}

	res.setHeader("Access-Control-Allow-Origin", origin);
	res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type");
	res.setHeader("Access-Control-Max-Age", "600");
	res.setHeader("Vary", "Origin");
	return true;
}

function videoFilename(id, extension) {
	return `${id}.${extension}`;
}

function videoKey(id, extension) {
	return `videos/${videoFilename(id, extension)}`;
}

function isNotFound(error) {
	return error.name === "NotFound" || error.name === "NoSuchKey" || error.$metadata?.httpStatusCode === 404;
}

function uploadSizeLimit() {
	return new Transform({
		transform(chunk, encoding, callback) {
			this.bytesReceived = (this.bytesReceived || 0) + chunk.length;
			if (this.bytesReceived > MAX_UPLOAD_SIZE) {
				const error = new Error("Upload exceeds the 100 MB limit.");
				error.code = "UPLOAD_TOO_LARGE";
				callback(error);
				return;
			}
			callback(null, chunk);
		}
	});
}

async function listVideos() {
	if (!r2) {
		const entries = await fs.promises.readdir(UPLOAD_DIR, { withFileTypes: true }).catch(error => {
			if (error.code === "ENOENT") return [];
			throw error;
		});
		return Promise.all(entries
			.filter(entry => entry.isFile() && /\.(mp4|webm|mov|mkv)$/i.test(entry.name))
			.map(async entry => {
				const stats = await fs.promises.stat(path.join(UPLOAD_DIR, entry.name));
				return {
					id: path.parse(entry.name).name,
					filename: entry.name,
					size: stats.size,
					updatedAt: stats.mtime.toISOString()
				};
			}));
	}

	const videos = [];
	let continuationToken;
	do {
		const result = await r2.send(new ListObjectsV2Command({
			Bucket: r2Bucket,
			Prefix: "videos/",
			ContinuationToken: continuationToken
		}));
		for (const object of result.Contents || []) {
			const filename = path.posix.basename(object.Key || "");
			if (!/^[A-Za-z0-9_-]{1,80}\.(mp4|webm|mov|mkv)$/i.test(filename)) continue;
			videos.push({
				id: path.parse(filename).name,
				filename,
				size: object.Size,
				updatedAt: object.LastModified?.toISOString()
			});
		}
		continuationToken = result.IsTruncated ? result.NextContinuationToken : undefined;
	} while (continuationToken);
	return videos;
}

async function saveVideo(req, id, extension) {
	if (!r2) {
		await fs.promises.mkdir(UPLOAD_DIR, { recursive: true });
		const destination = path.join(UPLOAD_DIR, videoFilename(id, extension));
		try {
			await pipeline(req, uploadSizeLimit(), fs.createWriteStream(destination, { flags: "wx" }));
		} catch (error) {
			if (error.code !== "EEXIST") {
				await fs.promises.unlink(destination).catch(unlinkError => {
					if (unlinkError.code !== "ENOENT") throw unlinkError;
				});
			}
			throw error;
		}
		return destination;
	}

	const key = videoKey(id, extension);
	try {
		await r2.send(new HeadObjectCommand({ Bucket: r2Bucket, Key: key }));
		const error = new Error("A video with this id already exists.");
		error.code = "VIDEO_EXISTS";
		throw error;
	} catch (error) {
		if (error.code === "VIDEO_EXISTS") throw error;
		if (!isNotFound(error)) throw error;
	}

	const temporaryFile = path.join(os.tmpdir(), `pingute-${randomUUID()}.upload`);
	try {
		await pipeline(req, uploadSizeLimit(), fs.createWriteStream(temporaryFile, { flags: "wx" }));
		const stats = await fs.promises.stat(temporaryFile);
		await r2.send(new PutObjectCommand({
			Bucket: r2Bucket,
			Key: key,
			Body: fs.createReadStream(temporaryFile),
			ContentLength: stats.size,
			ContentType: Object.keys(VIDEO_TYPES).find(type => VIDEO_TYPES[type] === extension)
		}));
		return key;
	} finally {
		await fs.promises.unlink(temporaryFile).catch(error => {
			if (error.code !== "ENOENT") throw error;
		});
	}
}

async function readVideo(req, res, id) {
	for (const [contentType, extension] of Object.entries(VIDEO_TYPES)) {
		if (!r2) {
			const filePath = path.join(UPLOAD_DIR, videoFilename(id, extension));
			try {
				const stats = await fs.promises.stat(filePath);
				res.writeHead(200, {
					"Content-Type": contentType,
					"Content-Length": stats.size,
					"X-Content-Type-Options": "nosniff"
				});
				if (req.method === "HEAD") res.end();
				else await pipeline(fs.createReadStream(filePath), res);
				return true;
			} catch (error) {
				if (error.code !== "ENOENT") throw error;
			}
			continue;
		}

		try {
			const command = req.method === "HEAD" ? HeadObjectCommand : GetObjectCommand;
			const object = await r2.send(new command({ Bucket: r2Bucket, Key: videoKey(id, extension) }));
			res.writeHead(200, {
				"Content-Type": object.ContentType || contentType,
				...(object.ContentLength === undefined ? {} : { "Content-Length": object.ContentLength }),
				"X-Content-Type-Options": "nosniff"
			});
			if (req.method === "HEAD") res.end();
			else await pipeline(object.Body, res);
			return true;
		} catch (error) {
			if (!isNotFound(error)) throw error;
		}
	}
	return false;
}

async function handleApi(req, res, url) {
	const match = url.pathname.match(/^\/api\/videos\/([A-Za-z0-9_-]{1,80})$/);

	if (url.pathname === "/api/health" && req.method === "GET") {
		sendJson(res, 200, { status: "ok", storage: r2 ? "cloudflare-r2" : "local" });
		return true;
	}

	if (url.pathname === "/api/videos" && req.method === "GET") {
		sendJson(res, 200, await listVideos());
		return true;
	}

	if (!match) return false;
	const id = match[1];
	if (req.method === "POST") {
		const contentType = (req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
		const extension = VIDEO_TYPES[contentType];
		if (!extension) {
			sendJson(res, 415, { error: "Upload a video/mp4, video/webm, video/quicktime, or video/x-matroska file." });
			return true;
		}

		const declaredSize = Number(req.headers["content-length"]);
		if (Number.isFinite(declaredSize) && declaredSize > MAX_UPLOAD_SIZE) {
			sendJson(res, 413, { error: "Video exceeds the 100 MB upload limit." });
			return true;
		}

		try {
			const storedAs = await saveVideo(req, id, extension);
			sendJson(res, 201, { id, filename: path.basename(storedAs), storage: r2 ? "r2" : "local" });
		} catch (error) {
			if (error.code === "EEXIST" || error.code === "VIDEO_EXISTS") {
				sendJson(res, 409, { error: "A video with this id already exists." });
			} else if (error.code === "UPLOAD_TOO_LARGE") {
				sendJson(res, 413, { error: "Video exceeds the 100 MB upload limit." });
			} else {
				throw error;
			}
		}
		return true;
	}

	if (req.method === "GET" || req.method === "HEAD") {
		if (!await readVideo(req, res, id)) sendJson(res, 404, { error: "Video not found." });
		return true;
	}

	res.setHeader("Allow", "GET, HEAD, POST");
	sendJson(res, 405, { error: "Method not allowed." });
	return true;
}

async function serveStatic(req, res, url) {
	if (req.method !== "GET" && req.method !== "HEAD") {
		res.setHeader("Allow", "GET, HEAD");
		sendJson(res, 405, { error: "Method not allowed." });
		return;
	}

	let pathname;
	try {
		pathname = decodeURIComponent(url.pathname);
	} catch {
		sendJson(res, 400, { error: "Invalid URL path." });
		return;
	}

	if (pathname.includes("\0") || pathname.includes("\\")) {
		sendJson(res, 400, { error: "Invalid URL path." });
		return;
	}

	const relativePath = pathname === "/" ? "index.html" : pathname.slice(1);
	const pathSegments = relativePath.split(path.sep);
	if (pathSegments.some(segment => segment.startsWith("."))
		|| relativePath === "server.js"
		|| !STATIC_TYPES[path.extname(relativePath).toLowerCase()]) {
		sendJson(res, 404, { error: "Not found." });
		return;
	}

	const filePath = path.resolve(ROOT, relativePath);
	const relativeToRoot = path.relative(ROOT, filePath);
	const relativeToUploads = path.relative(UPLOAD_DIR, filePath);
	if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)
		|| (relativeToUploads !== ".." && !relativeToUploads.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeToUploads))) {
		sendJson(res, 404, { error: "Not found." });
		return;
	}

	try {
		const stats = await fs.promises.stat(filePath);
		if (!stats.isFile()) {
			sendJson(res, 404, { error: "Not found." });
			return;
		}
		res.writeHead(200, {
			"Content-Type": STATIC_TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream",
			"Content-Length": stats.size,
			"X-Content-Type-Options": "nosniff"
		});
		if (req.method === "HEAD") {
			res.end();
		} else {
			await pipeline(fs.createReadStream(filePath), res);
		}
	} catch (error) {
		if (error.code === "ENOENT" || error.code === "EISDIR") {
			sendJson(res, 404, { error: "Not found." });
			return;
		}
		throw error;
	}
}

async function handleRequest(req, res) {
	try {
		if (!handleCors(req, res)) return;
		if (req.method === "OPTIONS") {
			res.writeHead(204);
			res.end();
			return;
		}

		const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
		if (url.pathname.startsWith("/api/")) {
			const handled = await handleApi(req, res, url);
			if (!handled) sendJson(res, 404, { error: "API endpoint not found." });
		} else {
			await serveStatic(req, res, url);
		}
	} catch (error) {
		console.error("Request failed:", error);
		if (!res.headersSent) sendJson(res, 500, { error: "Internal server error." });
		else res.destroy(error);
	}
}

http.createServer((req, res) => {
	void handleRequest(req, res);
}).listen(PORT, "0.0.0.0", () => {
	console.log(`Pingute server listening on port ${PORT}`);
});