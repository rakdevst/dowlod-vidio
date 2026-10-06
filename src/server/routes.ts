import express, { Request, Response, Router } from 'express';
import { Readable } from 'node:stream';
import { analyzeVideoUrl, validateUrlSafety } from './analyzer.ts';

export const apiRouter = Router();

// Middleware: parse JSON
apiRouter.use(express.json());

// 1. Health check
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'Video Stream Analyzer & Download Foundation',
  });
});

// 2. POST /api/analyze - URL Analysis
apiRouter.post('/analyze', async (req: Request, res: Response) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || !url.trim()) {
      res.status(400).json({
        status: 'error',
        errorCode: 'INVALID_URL',
        message: 'URL tidak boleh kosong. Harap masukkan URL video yang valid.',
      });
      return;
    }

    const result = await analyzeVideoUrl(url.trim());

    if (result.status === 'error') {
      const statusCode =
        result.errorCode === 'SSRF_BLOCKED' ? 403 :
        result.errorCode === 'DRM_PROTECTED' ? 422 :
        result.errorCode === 'AUTH_REQUIRED' ? 401 :
        result.errorCode === 'STREAMING_ENCRYPTED' ? 422 :
        result.errorCode === 'NO_MEDIA_FOUND' ? 404 :
        result.errorCode === 'TIMEOUT' ? 504 : 400;

      res.status(statusCode).json(result);
      return;
    }

    res.status(200).json(result);
  } catch (error: unknown) {
    const err = error as Error;
    res.status(500).json({
      status: 'error',
      errorCode: 'UNKNOWN_ERROR',
      message: 'Terjadi kesalahan internal server saat memproses analisis.',
      technicalDetails: err?.message || 'Internal Server Error',
    });
  }
});

// 3. Download handler function (reusable for GET and POST)
async function handleDownloadStream(targetUrl: string, requestedFilename: string | undefined, res: Response) {
  const safety = validateUrlSafety(targetUrl);
  if (!safety.isValid || !safety.parsed) {
    res.status(403).json({
      status: 'error',
      errorCode: 'SSRF_BLOCKED',
      message: 'URL download tidak diizinkan atau tidak aman.',
    });
    return;
  }

  const cleanFilename = (requestedFilename || 'downloaded_video.mp4')
    .replace(/[^\w.-]/g, '_')
    .substring(0, 100);

  try {
    const upstream = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept': '*/*',
      },
    });

    if (!upstream.ok) {
      res.status(upstream.status).json({
        status: 'error',
        errorCode: 'NETWORK_ERROR',
        message: `Gagal mengambil stream dari sumber: HTTP ${upstream.status}`,
      });
      return;
    }

    if (!upstream.body) {
      res.status(500).json({
        status: 'error',
        errorCode: 'NETWORK_ERROR',
        message: 'Stream data kosong dari server sumber.',
      });
      return;
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const contentLength = upstream.headers.get('content-length');

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${cleanFilename}"`);
    if (contentLength) {
      res.setHeader('Content-Length', contentLength);
    }
    res.setHeader('Cache-Control', 'no-cache');

    // Convert Web ReadableStream to Node Readable and pipe to response
    // Node 18+ supports Readable.fromWeb
    // @ts-expect-error Readable.fromWeb type definitions
    const nodeStream = Readable.fromWeb(upstream.body);
    nodeStream.pipe(res);

    nodeStream.on('error', (err: Error) => {
      console.error('Error streaming download:', err);
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
  } catch (err: unknown) {
    const errorObj = err as Error;
    if (!res.headersSent) {
      res.status(500).json({
        status: 'error',
        errorCode: 'NETWORK_ERROR',
        message: 'Gagal melakukan streaming pengunduhan file video.',
        technicalDetails: errorObj?.message,
      });
    }
  }
}

// 4. GET /api/download - Streaming file download
apiRouter.get('/download', async (req: Request, res: Response) => {
  const targetUrl = req.query.url as string;
  const filename = req.query.filename as string | undefined;

  if (!targetUrl) {
    res.status(400).json({
      status: 'error',
      errorCode: 'INVALID_URL',
      message: 'Parameter URL query tidak ditemukan.',
    });
    return;
  }

  await handleDownloadStream(targetUrl, filename, res);
});

// 5. POST /api/download - Streaming file download with JSON body
apiRouter.post('/download', async (req: Request, res: Response) => {
  const { url, filename } = req.body;

  if (!url) {
    res.status(400).json({
      status: 'error',
      errorCode: 'INVALID_URL',
      message: 'Field url tidak ditemukan pada body request.',
    });
    return;
  }

  await handleDownloadStream(url, filename, res);
});
