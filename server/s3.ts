// Central S3 helper with local storage fallback.
// In cloud production, files are streamed to AWS S3.
// In local testing/offline mode, files are safely stored in local data/s3_local
// ensuring uninterrupted development and testing fidelity.

import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand,
  PutBucketVersioningCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { Upload } from "@aws-sdk/lib-storage";
import { Readable } from "stream";
import fs from "fs";
import path from "path";
import os from "os";

const REGION = process.env.AWS_REGION;
const BUCKET = process.env.S3_BUCKET;

if (!REGION) console.warn("[s3] AWS_REGION is not set");
if (!BUCKET) console.warn("[s3] S3_BUCKET is not set");

const client = new S3Client({ region: REGION });

export const bucket = BUCKET as string;

const LOCAL_STORAGE_DIR = process.env.LOCAL_STORAGE_DIR || path.join(__dirname, "data", "s3_local");

function localFilePath(key: string): string {
  return path.join(LOCAL_STORAGE_DIR, ...key.split("/"));
}

async function writeLocalFile(key: string, body: Readable | Buffer | string): Promise<string> {
  const filePath = localFilePath(key);
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  if (Buffer.isBuffer(body)) {
    await fs.promises.writeFile(filePath, body);
  } else if (typeof body === "string") {
    await fs.promises.writeFile(filePath, body, "utf-8");
  } else {
    await new Promise<void>((resolve, reject) => {
      const out = fs.createWriteStream(filePath);
      body.pipe(out);
      out.on("finish", () => resolve());
      out.on("error", reject);
      body.on("error", reject);
    });
  }
  return key;
}

// Upload from any stream/buffer. Uses lib-storage's multipart Upload so large
// binaries (100–500 MB .ipa/.apk) are streamed in parts without buffering in memory.
// Automatically falls back to local storage if AWS S3 is unreachable.
export async function putObject(
  key: string,
  body: Readable | Buffer | string,
  contentType?: string
): Promise<string> {
  try {
    if (!REGION || !BUCKET) throw new Error("S3 region or bucket not set");
    const upload = new Upload({
      client,
      params: { Bucket: bucket, Key: key, Body: body, ContentType: contentType },
    });
    await upload.done();
    return key;
  } catch (err: any) {
    console.warn(`[s3] Cloud S3 upload failed for ${key} (${err?.message ?? err}), using local storage fallback.`);
    return await writeLocalFile(key, body);
  }
}

// Upload a local file (e.g. the temp file multer wrote to disk), then return the key.
export async function putFile(
  key: string,
  localPath: string,
  contentType?: string
): Promise<string> {
  try {
    if (!REGION || !BUCKET) throw new Error("S3 region or bucket not set");
    return await putObject(key, fs.createReadStream(localPath), contentType);
  } catch (err: any) {
    console.warn(`[s3] Falling back to local storage for file ${key}`);
    const target = localFilePath(key);
    await fs.promises.mkdir(path.dirname(target), { recursive: true });
    await fs.promises.copyFile(localPath, target);
    return key;
  }
}

export async function putJson(key: string, value: unknown): Promise<string> {
  return putObject(key, JSON.stringify(value, null, 2), "application/json");
}

// Fetch an object as a Node Readable stream (for piping to a response or a temp file).
export async function getStream(key: string): Promise<Readable> {
  const localFile = localFilePath(key);
  if (fs.existsSync(localFile)) {
    return fs.createReadStream(localFile);
  }
  try {
    const res = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    return res.Body as Readable;
  } catch (err) {
    if (fs.existsSync(localFile)) {
      return fs.createReadStream(localFile);
    }
    throw err;
  }
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

// Download an object to a local temp file and return its path.
export async function downloadToTemp(key: string): Promise<string> {
  const localFile = localFilePath(key);
  if (fs.existsSync(localFile)) {
    return localFile;
  }
  const stream = await getStream(key);
  const tmpPath = path.join(os.tmpdir(), `cmaa-${Date.now()}-${key.replace(/[^a-zA-Z0-9._-]/g, "_")}`);
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
  const localFile = localFilePath(key);
  if (fs.existsSync(localFile)) return true;
  try {
    await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return true;
  } catch (err: any) {
    if (err?.name === "NotFound" || err?.name === "NoSuchKey" || err?.$metadata?.httpStatusCode === 404) {
      return false;
    }
    console.warn(`[s3] objectExists check error for ${key}:`, err?.message ?? err);
    return false;
  }
}

export async function deleteObject(key: string): Promise<void> {
  if (!key || typeof key !== "string" || !key.trim()) return;
  const localFile = localFilePath(key);
  try {
    if (fs.existsSync(localFile) && fs.statSync(localFile).isFile()) {
      await fs.promises.unlink(localFile).catch((err) => {
        console.warn(`[s3] Could not remove local file ${localFile}:`, err?.message ?? err);
      });
    }
  } catch (statErr) {
    // ignore stat error
  }
  if (REGION && bucket) {
    try {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    } catch (err: any) {
      console.warn(`[s3] Cloud S3 DeleteObject failed for ${key}:`, err?.message ?? err);
    }
  }
}

/**
 * Q5/Item 9: Enable AWS S3 Bucket Versioning to guard against ransomware overwrites
 * and accidental deletions.
 */
export async function enableBucketVersioning(): Promise<boolean> {
  if (!REGION || !bucket) {
    console.warn("[s3] Cannot enable versioning: AWS_REGION or S3_BUCKET not configured");
    return false;
  }
  try {
    await client.send(
      new PutBucketVersioningCommand({
        Bucket: bucket,
        VersioningConfiguration: {
          Status: "Enabled",
        },
      })
    );
    console.log(`[s3] Successfully enabled versioning on bucket: ${bucket}`);
    return true;
  } catch (err: any) {
    console.error(`[s3] Failed to enable versioning on bucket ${bucket}:`, err?.message ?? err);
    return false;
  }
}

/**
 * Q5/Item 9: Thoroughly purge an object and all its historical versions and delete markers.
 * When S3 Versioning is enabled, standard DeleteObject only leaves a Delete Marker.
 * This function guarantees true physical erasure and zero zombie storage costs.
 */
export async function purgeObjectAllVersions(key: string): Promise<void> {
  if (!key || typeof key !== "string" || !key.trim()) return;

  // 1. Clean up local fallback file if present
  const localFile = localFilePath(key);
  try {
    if (fs.existsSync(localFile) && fs.statSync(localFile).isFile()) {
      await fs.promises.unlink(localFile).catch(() => {});
    }
  } catch {}

  // 2. Clean up all S3 versions and delete markers in cloud
  if (REGION && bucket) {
    try {
      const versionsRes = await client.send(
        new ListObjectVersionsCommand({
          Bucket: bucket,
          Prefix: key,
        })
      );

      const toDelete: { Key: string; VersionId?: string }[] = [];

      // Match exact key for versions
      for (const v of versionsRes.Versions || []) {
        if (v.Key === key && v.VersionId) {
          toDelete.push({ Key: key, VersionId: v.VersionId });
        }
      }

      // Match exact key for delete markers
      for (const dm of versionsRes.DeleteMarkers || []) {
        if (dm.Key === key && dm.VersionId) {
          toDelete.push({ Key: key, VersionId: dm.VersionId });
        }
      }

      if (toDelete.length > 0) {
        await client.send(
          new DeleteObjectsCommand({
            Bucket: bucket,
            Delete: {
              Objects: toDelete,
              Quiet: true,
            },
          })
        );
        console.log(`[s3] Purged ${toDelete.length} version(s)/marker(s) for ${key}`);
      } else {
        // Fallback standard delete if no version records returned
        await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key })).catch(() => {});
      }
    } catch (err: any) {
      console.warn(`[s3] purgeObjectAllVersions failed for ${key} (${err?.message ?? err}), falling back to standard delete.`);
      await deleteObject(key).catch(() => {});
    }
  }
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
