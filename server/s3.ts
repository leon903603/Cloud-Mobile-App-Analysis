// Central S3 helper. All file bytes (uploaded binaries + report artifacts) live in
// S3; SQLite keeps only the object keys (in the existing filePath/reportPath/uploadPath
// fields). Credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) are read from the
// environment automatically by the SDK; region + bucket are read explicitly here.

import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Upload } from "@aws-sdk/lib-storage";
import { Readable } from "stream";
import fs from "fs";

const REGION = process.env.AWS_REGION;
const BUCKET = process.env.S3_BUCKET;

if (!REGION) console.warn("[s3] AWS_REGION is not set");
if (!BUCKET) console.warn("[s3] S3_BUCKET is not set");

const client = new S3Client({ region: REGION });

export const bucket = BUCKET as string;

// Upload from any stream/buffer. Uses lib-storage's multipart Upload so large
// binaries (100–500 MB .ipa/.apk) are streamed in parts without buffering in memory.
export async function putObject(
  key: string,
  body: Readable | Buffer | string,
  contentType?: string
): Promise<string> {
  const upload = new Upload({
    client,
    params: { Bucket: bucket, Key: key, Body: body, ContentType: contentType },
  });
  await upload.done();
  return key;
}

// Upload a local file (e.g. the temp file multer wrote to disk), then return the key.
export async function putFile(
  key: string,
  localPath: string,
  contentType?: string
): Promise<string> {
  return putObject(key, fs.createReadStream(localPath), contentType);
}

export async function putJson(key: string, value: unknown): Promise<string> {
  return putObject(key, JSON.stringify(value, null, 2), "application/json");
}

// Fetch an object as a Node Readable stream (for piping to a response or a temp file).
export async function getStream(key: string): Promise<Readable> {
  const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return res.Body as Readable;
}

export async function getBuffer(key: string): Promise<Buffer> {
  const stream = await getStream(key);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

export async function getJson<T = any>(key: string): Promise<T> {
  const buf = await getBuffer(key);
  return JSON.parse(buf.toString("utf-8")) as T;
}

// Download an object to a local temp file and return its path. Used before building a
// multipart form for the analysis wrappers, which need a known Content-Length.
export async function downloadToTemp(key: string): Promise<string> {
  const stream = await getStream(key);
  const tmpPath = `/tmp/cmaa-${Date.now()}-${key.replace(/[^a-zA-Z0-9._-]/g, "_")}`;
  await new Promise<void>((resolve, reject) => {
    const out = fs.createWriteStream(tmpPath);
    stream.pipe(out);
    out.on("finish", () => resolve());
    out.on("error", reject);
    stream.on("error", reject);
  });
  return tmpPath;
}

export async function objectExists(key: string): Promise<boolean> {
  try {
    await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    return true;
  } catch {
    return false;
  }
}

export async function deleteObject(key: string): Promise<void> {
  await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
}

export async function getPresignedDownloadUrl(
  key: string,
  filename?: string,
  expiresIn = 300 // 5 minutes default
): Promise<string> {
  const command = new GetObjectCommand({
    Bucket: bucket,
    Key: key,
    ResponseContentDisposition: filename
      ? `attachment; filename="${encodeURIComponent(filename)}"`
      : undefined,
  });
  return getSignedUrl(client, command, { expiresIn });
}
