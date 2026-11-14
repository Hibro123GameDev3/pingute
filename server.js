const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const {
	createHash,
	randomBytes,
	randomUUID,
	scrypt: scryptCallback,
	timingSafeEqual
} = require("node:crypto");
const { promisify } = require("node:util");
const { Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const {
	S3Client,
	PutObjectCommand,
	GetObjectCommand,
	DeleteObjectCommand,
	HeadObjectCommand,
	ListObjectsV2Command
} = require("@aws-sdk/client-s3");

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(ROOT, "uploads"));
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024;
const MAX_AUTH_BODY_SIZE = 8 * 1024;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const AUTH_COOKIE_NAME = "pingute_session";
const SCRYPT_OPTIONS = { N: 1 << 14, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const scrypt = promisify(scryptCallback);
const authRateLimits = new Map();
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

function sendAuthJson(res, status, data) {
	res.setHeader("Cache-Control", "no-store");
	sendJson(res, status, data);
}

function isTrustedRequestOrigin(req) {
	const origin = req.headers.origin;
	if (!origin) return false;

	try {
		const parsedOrigin = new URL(origin);
		return parsedOrigin.origin === origin
			&& (parsedOrigin.host === req.headers.host || FRONTEND_ORIGINS.has(origin));
	} catch {
		return false;
	}
}

function authClientKey(req, action) {
	const forwardedFor = req.headers["x-forwarded-for"];
	const address = typeof forwardedFor === "string"
		? forwardedFor.split(",")[0].trim()
		: req.socket.remoteAddress || "unknown";
	return `${action}:${address}`;
}

function allowAuthAttempt(req, res, action, limit, windowMs) {
	const now = Date.now();
	for (const [key, entry] of authRateLimits) {
		if (entry.expiresAt <= now) authRateLimits.delete(key);
	}

	const key = authClientKey(req, action);
	const entry = authRateLimits.get(key);
	if (entry && entry.count >= limit) {
		sendAuthJson(res, 429, { error: "Too many attempts. Please try again later." });
		return false;
	}
	if (entry) {
		entry.count += 1;
	} else {
		authRateLimits.set(key, { count: 1, expiresAt: now + windowMs });
	}
	if (authRateLimits.size > 10000) authRateLimits.delete(authRateLimits.keys().next().value);
	return true;
}

function clearAuthAttempts(req, action) {
	authRateLimits.delete(authClientKey(req, action));
}

function setSessionCookie(res, token, maxAge) {
	const secure = Boolean(process.env.RENDER) || process.env.NODE_ENV === "production";
	res.setHeader("Set-Cookie", [
		`${AUTH_COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=${secure ? "None" : "Lax"}; Max-Age=${maxAge}${secure ? "; Secure" : ""}`
	]);
}

function readCookie(req, name) {
	const cookies = req.headers.cookie || "";
	for (const cookie of cookies.split(";")) {
		const separator = cookie.indexOf("=");
		if (separator < 0) continue;
		if (cookie.slice(0, separator).trim() === name) return cookie.slice(separator + 1).trim();
	}
	return null;
}

async function readAuthJson(req) {
	if ((req.headers["content-type"] || "").split(";")[0].trim().toLowerCase() !== "application/json") {
		const error = new Error("Send the request as JSON.");
		error.code = "AUTH_UNSUPPORTED_MEDIA";
		throw error;
	}

	const chunks = [];
	let bytesRead = 0;
	let tooLarge = false;
	await new Promise((resolve, reject) => {
		req.on("data", chunk => {
			bytesRead += chunk.length;
			if (bytesRead > MAX_AUTH_BODY_SIZE) {
				tooLarge = true;
				chunks.length = 0;
				return;
			}
			if (!tooLarge) chunks.push(chunk);
		});
		req.once("end", resolve);
		req.once("error", reject);
	});

	if (tooLarge) {
		const error = new Error("Request body is too large.");
		error.code = "AUTH_BODY_TOO_LARGE";
		throw error;
	}
	try {
		const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
		if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
		return value;
	} catch {
		const error = new Error("Send a valid JSON object.");
		error.code = "AUTH_INVALID_JSON";
		throw error;
	}
}

function authUser(record) {
	if (!record || typeof record.id !== "string" || typeof record.username !== "string"
		|| typeof record.createdAt !== "string") {
		throw new Error("Stored account record is invalid.");
	}
	return { id: record.id, username: record.username, createdAt: record.createdAt };
}

function userObjectKey(username) {
	return `users/${username.toLowerCase()}.json`;
}

function sessionObjectKey(token) {
	return `sessions/${createHash("sha256").update(token).digest("hex")}.json`;
}

async function readR2Json(key, { req, res } = {}) {
	let object;
	try {
		object = await sendR2(new GetObjectCommand({ Bucket: r2Bucket, Key: key }), { req, res });
	} catch (error) {
		if (isNotFound(error)) return null;
		throw error;
	}

	try {
		return JSON.parse(await object.Body.transformToString());
	} catch (error) {
		if (error instanceof SyntaxError) throw new Error("Account storage contains invalid JSON.");
		throw error;
	}
}

async function writeR2Json(key, value, { onlyIfAbsent = false, req, res } = {}) {
	await sendR2(new PutObjectCommand({
		Bucket: r2Bucket,
		Key: key,
		Body: JSON.stringify(value),
		ContentType: "application/json",
		...(onlyIfAbsent ? { IfNoneMatch: "*" } : {})
	}), { req, res });
}

function isConditionalWriteFailure(error) {
	return error.name === "PreconditionFailed" || error.$metadata?.httpStatusCode === 412;
}

async function createAuthSession(usernameKey, req, res) {
	const token = randomBytes(32).toString("base64url");
	const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
	await writeR2Json(sessionObjectKey(token), {
		usernameKey,
		expiresAt: expiresAt.toISOString()
	}, { onlyIfAbsent: true, req, res });
	const previousToken = readCookie(req, AUTH_COOKIE_NAME);
	if (previousToken && previousToken !== token && /^[A-Za-z0-9_-]{43}$/.test(previousToken)) {
		await sendR2(new DeleteObjectCommand({
			Bucket: r2Bucket,
			Key: sessionObjectKey(previousToken)
		}), { req, res });
	}
	setSessionCookie(res, token, SESSION_TTL_SECONDS);
}

async function currentAuthUser(req, res) {
	const token = readCookie(req, AUTH_COOKIE_NAME);
	if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
	const key = sessionObjectKey(token);
	const session = await readR2Json(key, { req, res });
	if (!session) return null;
	if (typeof session.usernameKey !== "string"
		|| !/^[a-zA-Z0-9_]{3,24}$/.test(session.usernameKey)
		|| typeof session.expiresAt !== "string") {
		throw new Error("Stored session record is invalid.");
	}

	const expiresAt = Date.parse(session.expiresAt);
	if (!Number.isFinite(expiresAt)) throw new Error("Stored session expiry is invalid.");
	if (expiresAt <= Date.now()) {
		await sendR2(new DeleteObjectCommand({ Bucket: r2Bucket, Key: key }), { req, res });
		return null;
	}
	return readR2Json(userObjectKey(session.usernameKey), { req, res });
}

async function handleAuth(req, res, url) {
	const route = url.pathname;
	const method = req.method;
	const allowedMethod = new Map([
		["/api/auth/me", "GET"],
		["/api/auth/signup", "POST"],
		["/api/auth/signin", "POST"],
		["/api/auth/signout", "POST"]
	]).get(route);
	if (!allowedMethod) return false;
	if (method !== allowedMethod) {
		res.setHeader("Allow", allowedMethod);
		sendAuthJson(res, 405, { error: "Method not allowed." });
		return true;
	}

	if (!r2) {
		sendAuthJson(res, 503, { error: "Cloudflare R2 account storage is not configured on the server." });
		return true;
	}

	if (method === "GET") {
		const user = await currentAuthUser(req, res);
		sendAuthJson(res, 200, { user: user ? authUser(user) : null });
		return true;
	}

	if (!isTrustedRequestOrigin(req)) {
		sendAuthJson(res, 403, { error: "This website is not allowed to use account actions." });
		return true;
	}

	if (route === "/api/auth/signout") {
		const token = readCookie(req, AUTH_COOKIE_NAME);
		if (token && /^[A-Za-z0-9_-]{43}$/.test(token)) {
			await sendR2(new DeleteObjectCommand({
				Bucket: r2Bucket,
				Key: sessionObjectKey(token)
			}), { req, res });
		}
		setSessionCookie(res, "", 0);
		sendAuthJson(res, 200, { user: null });
		return true;
	}

	const isSignup = route === "/api/auth/signup";
	const action = isSignup ? "signup" : "signin";
	const limit = isSignup ? 5 : 10;
	const windowMs = isSignup ? 60 * 60 * 1000 : 15 * 60 * 1000;
	if (!allowAuthAttempt(req, res, action, limit, windowMs)) return true;

	let body;
	try {
		body = await readAuthJson(req);
	} catch (error) {
		const status = error.code === "AUTH_BODY_TOO_LARGE" ? 413
			: error.code === "AUTH_UNSUPPORTED_MEDIA" ? 415 : 400;
		sendAuthJson(res, status, { error: error.message });
		return true;
	}

	const username = typeof body.username === "string" ? body.username.trim() : "";
	const password = typeof body.password === "string" ? body.password : "";
	const validUsername = /^[A-Za-z0-9_]{3,24}$/.test(username);
	if (isSignup && (!validUsername || password.length < 12 || password.length > 128)) {
		sendAuthJson(res, 400, {
			error: "Choose a 3-24 character username (letters, numbers, underscores) and a 12-128 character password."
		});
		return true;
	}
	if (password.length > 128 || !validUsername) {
		sendAuthJson(res, 401, { error: "Invalid username or password." });
		return true;
	}

	if (isSignup) {
		const salt = randomBytes(16);
		const passwordHash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
		const account = {
			id: randomUUID(),
			username,
			passwordSalt: salt.toString("base64url"),
			passwordHash: passwordHash.toString("base64url"),
			createdAt: new Date().toISOString()
		};
		try {
			await writeR2Json(userObjectKey(username), account, { onlyIfAbsent: true, req, res });
		} catch (error) {
			if (isConditionalWriteFailure(error)) {
				sendAuthJson(res, 409, { error: "That username is already taken." });
				return true;
			}
			throw error;
		}
		await createAuthSession(username.toLowerCase(), req, res);
		sendAuthJson(res, 201, { user: authUser(account) });
		return true;
	}

	const account = await readR2Json(userObjectKey(username), { req, res });
	if (!account) {
		await scrypt(password, randomBytes(16), 64, SCRYPT_OPTIONS);
		sendAuthJson(res, 401, { error: "Invalid username or password." });
		return true;
	}

	if (typeof account.passwordSalt !== "string" || typeof account.passwordHash !== "string") {
		throw new Error("Stored account password data is invalid.");
	}
	const salt = Buffer.from(account.passwordSalt, "base64url");
	const storedHash = Buffer.from(account.passwordHash, "base64url");
	if (salt.length !== 16 || storedHash.length !== 64) {
		throw new Error("Stored account password data is invalid.");
	}
	const passwordHash = await scrypt(password, salt, 64, SCRYPT_OPTIONS);
	if (!timingSafeEqual(passwordHash, storedHash)) {
		sendAuthJson(res, 401, { error: "Invalid username or password." });
		return true;
	}

	clearAuthAttempts(req, action);
	await createAuthSession(username.toLowerCase(), req, res);
	sendAuthJson(res, 200, { user: authUser(account) });
	return true;
}

async function sendR2(command, { timeoutMs = 30000, req, res } = {}) {
	const controller = new AbortController();
	let timedOut = false;
	const abortRequest = () => controller.abort();
	const abortResponse = () => {
		if (!res.writableFinished) controller.abort();
	};
	const timeout = setTimeout(() => {
		timedOut = true;
		abortRequest();
	}, timeoutMs);

	if (req && res) {
		req.once("aborted", abortRequest);
		res.once("close", abortResponse);
		if (req.aborted || (res.destroyed && !res.writableFinished)) abortRequest();
	}

	try {
		return await r2.send(command, { abortSignal: controller.signal });
	} catch (error) {
		if (!timedOut) throw error;
		const timeoutError = new Error("Cloudflare R2 request timed out.");
		timeoutError.code = "R2_TIMEOUT";
		throw timeoutError;
	} finally {
		clearTimeout(timeout);
		if (req && res) {
			req.removeListener("aborted", abortRequest);
			res.removeListener("close", abortResponse);
		}
	}
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
	res.setHeader("Access-Control-Allow-Credentials", "true");
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

async function listVideos(req, res) {
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
		const result = await sendR2(new ListObjectsV2Command({
			Bucket: r2Bucket,
			Prefix: "videos/",
			ContinuationToken: continuationToken
		}), { req, res });
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

async function saveVideo(req, res, id, extension) {
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
		await sendR2(new HeadObjectCommand({ Bucket: r2Bucket, Key: key }), { timeoutMs: 15000, req, res });
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
		await sendR2(new PutObjectCommand({
			Bucket: r2Bucket,
			Key: key,
			Body: fs.createReadStream(temporaryFile),
			ContentLength: stats.size,
			ContentType: Object.keys(VIDEO_TYPES).find(type => VIDEO_TYPES[type] === extension)
		}), { timeoutMs: 120000, req, res });
		return key;
	} finally {
		await fs.promises.unlink(temporaryFile).catch(error => {
			if (error.code !== "ENOENT") throw error;
		});
	}
}

function parseByteRange(header, size) {
	if (!header) return null;
	const match = header.match(/^bytes=(\d*)-(\d*)$/);
	if (!match || (!match[1] && !match[2])) return { invalid: true };

	let start;
	let end;
	if (!match[1]) {
		const suffixLength = Number(match[2]);
		if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return { invalid: true };
		start = Math.max(size - suffixLength, 0);
		end = size - 1;
	} else {
		start = Number(match[1]);
		end = match[2] ? Number(match[2]) : size - 1;
		if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || start > end) {
			return { invalid: true };
		}
		end = Math.min(end, size - 1);
	}

	return { start, end, length: end - start + 1 };
}

async function readVideo(req, res, id) {
	for (const [contentType, extension] of Object.entries(VIDEO_TYPES)) {
		if (!r2) {
			const filePath = path.join(UPLOAD_DIR, videoFilename(id, extension));
			try {
				const stats = await fs.promises.stat(filePath);
				const range = req.method === "GET" ? parseByteRange(req.headers.range, stats.size) : null;
				if (range?.invalid) {
					res.writeHead(416, {
						"Accept-Ranges": "bytes",
						"Content-Range": `bytes */${stats.size}`
					});
					res.end();
					return true;
				}

				res.writeHead(range ? 206 : 200, {
					...(range ? {
						"Content-Range": `bytes ${range.start}-${range.end}/${stats.size}`,
						"Content-Length": range.length
					} : { "Content-Length": stats.size }),
					"Accept-Ranges": "bytes",
					"Content-Type": contentType,
					"X-Content-Type-Options": "nosniff"
				});
				if (req.method === "HEAD") res.end();
				else await pipeline(fs.createReadStream(filePath, range ? { start: range.start, end: range.end } : undefined), res);
				return true;
			} catch (error) {
				if (error.code !== "ENOENT") throw error;
			}
			continue;
		}

		try {
			const command = req.method === "HEAD" ? HeadObjectCommand : GetObjectCommand;
			const object = await sendR2(new command({
				Bucket: r2Bucket,
				Key: videoKey(id, extension),
				...(req.method === "GET" && req.headers.range ? { Range: req.headers.range } : {})
			}), { req, res });
			res.writeHead(object.ContentRange ? 206 : 200, {
				"Content-Type": object.ContentType || contentType,
				...(object.ContentLength === undefined ? {} : { "Content-Length": object.ContentLength }),
				...(object.ContentRange ? { "Content-Range": object.ContentRange } : {}),
				"Accept-Ranges": "bytes",
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

	if (url.pathname.startsWith("/api/auth/") && await handleAuth(req, res, url)) {
		return true;
	}

	if (url.pathname === "/api/health" && req.method === "GET") {
		sendJson(res, 200, { status: "ok", storage: r2 ? "cloudflare-r2" : "local" });
		return true;
	}

	if (url.pathname === "/api/videos" && req.method === "GET") {
		sendJson(res, 200, await listVideos(req, res));
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
			const storedAs = await saveVideo(req, res, id, extension);
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
		if (["ABORT_ERR", "ECONNRESET", "EPIPE", "ERR_STREAM_PREMATURE_CLOSE"].includes(error.code)) {
			if (!res.destroyed) res.destroy();
			return;
		}

		console.error("Request failed:", error);
		if (!res.headersSent && !res.destroyed) {
			const timedOut = error.code === "R2_TIMEOUT";
			sendJson(res, timedOut ? 504 : 500, {
				error: timedOut ? error.message : "Internal server error."
			});
		}
		else if (!res.destroyed) res.destroy();
	}
}

http.createServer((req, res) => {
	void handleRequest(req, res);
}).listen(PORT, "0.0.0.0", () => {
	console.log(`Pingute server listening on port ${PORT}`);
});