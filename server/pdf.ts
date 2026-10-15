// server/pdf.ts — PDF report generation via a private Lambda.
//
// Replaces the always-on pdf-generator container (which competed for RAM on the
// 1 GiB EC2 box). The Lambda reads the report JSON from S3, renders it, writes the
// PDF back to S3 and returns a presigned URL, so report bytes never transit this
// server. It is invoked with the SDK rather than a Function URL — a public
// endpoint would let anyone mint presigned links for arbitrary report keys.

import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

const REGION = process.env.AWS_REGION ?? "ap-southeast-2";
const STATIC_PDF_LAMBDA_NAME = process.env.STATIC_PDF_LAMBDA_NAME ?? process.env.PDF_LAMBDA_NAME ?? "cmaa-static-pdf-report";
const DYNAMIC_PDF_LAMBDA_NAME = process.env.DYNAMIC_PDF_LAMBDA_NAME ?? "cmaa-dynamic-pdf-report";

const client = new LambdaClient({ region: REGION });

export interface RenderPdfOk {
  ok: true;
  url: string;
  key: string;
  bytes: number;
  expires_in: number;
}

export interface RenderPdfErr {
  ok: false;
  error: string;
}

export type RenderPdfResult = RenderPdfOk | RenderPdfErr;

export async function renderReportPdf(opts: {
  reportKey: string;
  filename?: string;
  lang?: string;
  outputKey?: string;
  type?: string;
  functionName?: string;
}): Promise<RenderPdfResult> {
  if (process.env.MOCK_PDF === "true") {
    if (opts.outputKey) {
      const { putObject } = await import("./s3");
      const dummy = Buffer.from("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>startxref\n0\n%%EOF");
      await putObject(opts.outputKey, dummy, "application/pdf").catch(() => {});
    }
    return {
      ok: true,
      url: `https://${process.env.S3_BUCKET || "cmaa-s3"}.s3.amazonaws.com/${opts.outputKey || "report.pdf"}`,
      key: opts.outputKey || "report.pdf",
      bytes: 1024,
      expires_in: 60,
    };
  }

  const isDynamic = opts.type === "dynamic" || opts.type === "android-dynamic";
  const defaultTarget = isDynamic ? DYNAMIC_PDF_LAMBDA_NAME : STATIC_PDF_LAMBDA_NAME;
  const targetFunction = opts.functionName || defaultTarget;
  const payload = {
    report_key: opts.reportKey,
    filename: opts.filename,
    lang: opts.lang,
    output_key: opts.outputKey,
  };

  const out = await client.send(
    new InvokeCommand({
      FunctionName: targetFunction,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify(payload)),
    }),
  );

  if (out.FunctionError) {
    const detail = out.Payload ? Buffer.from(out.Payload).toString("utf-8") : "";
    return { ok: false, error: `${out.FunctionError}: ${detail.slice(0, 500)}` };
  }
  if (!out.Payload) {
    return { ok: false, error: "PDF Lambda returned an empty payload" };
  }

  try {
    return JSON.parse(Buffer.from(out.Payload).toString("utf-8")) as RenderPdfResult;
  } catch {
    return { ok: false, error: "PDF Lambda returned invalid JSON" };
  }
}
