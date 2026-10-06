import type { AnalyzeApiResponse, VideoFormat, VideoMetadata, AnalyzerErrorCode } from '../types/analyzer.ts';

// Helper to format bytes into readable sizes
export function formatBytes(bytes?: number): string {
  if (!bytes || isNaN(bytes) || bytes <= 0) return 'Ukuran tidak diketahui';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(2)} ${units[i]}`;
}

// Security: Prevent Server-Side Request Forgery (SSRF)
export function validateUrlSafety(rawUrl: string): { isValid: boolean; parsed?: URL; error?: string } {
  try {
    const parsed = new URL(rawUrl.trim());

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return {
        isValid: false,
        error: 'Hanya protokol HTTP dan HTTPS yang didukung.',
      };
    }

    const hostname = parsed.hostname.toLowerCase();

    // Check loopback, local, metadata IP
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname === '::1' ||
      hostname === '169.254.169.254' || // Cloud metadata service
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.localhost')
    ) {
      return {
        isValid: false,
        error: 'Akses ke jaringan lokal atau loopback diblokir demi keamanan (SSRF Protection).',
      };
    }

    // Check private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10)
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const ipMatch = hostname.match(ipv4Regex);
    if (ipMatch) {
      const octet1 = parseInt(ipMatch[1], 10);
      const octet2 = parseInt(ipMatch[2], 10);
      if (
        octet1 === 10 ||
        octet1 === 127 ||
        (octet1 === 172 && octet2 >= 16 && octet2 <= 31) ||
        (octet1 === 192 && octet2 === 168) ||
        (octet1 === 169 && octet2 === 254)
      ) {
        return {
          isValid: false,
          error: 'Akses ke IP privat/lokal diblokir demi keamanan server.',
        };
      }
    }

    return { isValid: true, parsed };
  } catch {
    return {
      isValid: false,
      error: 'Format URL tidak valid. Pastikan menyertakan http:// atau https://',
    };
  }
}

// Known DRM or strictly walled services
const KNOWN_DRM_DOMAINS = [
  'netflix.com',
  'disneyplus.com',
  'spotify.com',
  'hulu.com',
  'hbomax.com',
  'max.com',
  'primevideo.com',
  'apple.com/apple-tv-plus',
];

const KNOWN_AUTH_WALL_DOMAINS = [
  'instagram.com',
  'facebook.com',
  'fb.watch',
  'onlyfans.com',
  'patreon.com',
];

// Extract basic filename from URL or header
function extractFilename(urlObj: URL, contentDisposition?: string | null): string {
  if (contentDisposition) {
    const filenameMatch = contentDisposition.match(/filename\*?=['"]?(?:UTF-\d['"]*)?([^;\r\n"']*)['"]?/i);
    if (filenameMatch && filenameMatch[1]) {
      return decodeURIComponent(filenameMatch[1]);
    }
  }

  const pathnameParts = urlObj.pathname.split('/').filter(Boolean);
  const lastPart = pathnameParts[pathnameParts.length - 1];
  if (lastPart && lastPart.includes('.')) {
    return decodeURIComponent(lastPart);
  }

  return 'video_download_' + Date.now() + '.mp4';
}

export async function analyzeVideoUrl(rawUrl: string): Promise<AnalyzeApiResponse> {
  const urlCheck = validateUrlSafety(rawUrl);
  if (!urlCheck.isValid || !urlCheck.parsed) {
    return {
      status: 'error',
      errorCode: 'SSRF_BLOCKED',
      message: urlCheck.error || 'URL tidak aman atau format salah.',
      technicalDetails: 'Validasi keamanan URL backend menolak hostname ini.',
      legalNotice: 'Backend tidak diizinkan melakukan request ke endpoint privat atau lokal.',
    };
  }

  const parsedUrl = urlCheck.parsed;
  const hostname = parsedUrl.hostname.toLowerCase();

  // 1. Check known DRM platforms
  if (KNOWN_DRM_DOMAINS.some((d) => hostname.includes(d))) {
    return {
      status: 'error',
      errorCode: 'DRM_PROTECTED',
      message: 'Platform ini dilindungi proteksi hak cipta dan DRM (Digital Rights Management).',
      technicalDetails: `Domain ${hostname} menggunakan enkripsi Widevine/FairPlay hardware DRM.`,
      legalNotice: 'Aplikasi ini secara tegas mematuhi hukum hak cipta dan tidak melakukan bypass terhadap enkripsi DRM.',
      suggestion: 'Gunakan URL video publik, file terbuka, atau repositori media bebas hak cipta.',
    };
  }

  // 2. Check known authentication wall platforms
  if (KNOWN_AUTH_WALL_DOMAINS.some((d) => hostname.includes(d))) {
    return {
      status: 'error',
      errorCode: 'AUTH_REQUIRED',
      message: 'Platform ini memerlukan login akun pengguna atau terhalang access control.',
      technicalDetails: `Domain ${hostname} menerapkan session wall / anti-scraping cookie requirement.`,
      legalNotice: 'Aplikasi tidak membypass autentikasi atau melanggar kontrol akses akun privat.',
      suggestion: 'Pastikan media yang ingin diakses berstatus publik tanpa memerlukan login.',
    };
  }

  // 3. Check popular platforms that require complex signature decryption / bot token (e.g. YouTube, TikTok)
  if (hostname.includes('youtube.com') || hostname.includes('youtu.be')) {
    return {
      status: 'error',
      errorCode: 'STREAMING_ENCRYPTED',
      message: 'Platform video ini menggunakan sistem proteksi bot-challenge dan signature dinamis.',
      technicalDetails: 'YouTube tidak menyediakan direct static file; aliran data dipisah menjadi chunk DASH/HLS dengan n-sig cipher.',
      legalNotice: 'Sistem ini mematuhi standar integritas dan tidak membypass bot protection atau enkripsi signature pihak ketiga.',
      suggestion: 'Untuk pengujian, gunakan direct video stream (MP4/WebM) publik seperti Wikimedia Commons atau Archive.org.',
    };
  }

  // 4. Perform live request inspection on the URL
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

    // Try HEAD request first for efficiency
    let response: Response;
    let methodUsed = 'HEAD';
    try {
      response = await fetch(parsedUrl.toString(), {
        method: 'HEAD',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Accept': '*/*',
        },
        signal: controller.signal,
        redirect: 'follow',
      });

      // If HEAD is not allowed (405) or not implemented, fallback to GET with Range
      if (response.status === 405 || response.status === 501) {
        methodUsed = 'GET';
        response = await fetch(parsedUrl.toString(), {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Range': 'bytes=0-1024',
          },
          signal: controller.signal,
          redirect: 'follow',
        });
      }
    } catch {
      // Fallback to GET directly if HEAD failed
      methodUsed = 'GET';
      response = await fetch(parsedUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Range': 'bytes=0-1024',
        },
        signal: controller.signal,
        redirect: 'follow',
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok && response.status !== 206) {
      return {
        status: 'error',
        errorCode: 'NETWORK_ERROR',
        message: `Server sumber merespons dengan status HTTP ${response.status} (${response.statusText}).`,
        technicalDetails: `Request ${methodUsed} ke ${parsedUrl.origin} gagal dengan kode status ${response.status}.`,
        suggestion: 'Periksa apakah URL masih aktif dan dapat diakses di browser.',
      };
    }

    const contentType = response.headers.get('content-type') || '';
    const contentLengthHeader = response.headers.get('content-length');
    const contentRangeHeader = response.headers.get('content-range');
    const contentDisposition = response.headers.get('content-disposition');
    const acceptRanges = response.headers.get('accept-ranges') === 'bytes' || response.status === 206;

    let sizeBytes: number | undefined;
    if (contentLengthHeader) {
      sizeBytes = parseInt(contentLengthHeader, 10);
    } else if (contentRangeHeader) {
      // e.g. bytes 0-1024/15482910
      const totalMatch = contentRangeHeader.match(/\/(\d+)$/);
      if (totalMatch && totalMatch[1]) {
        sizeBytes = parseInt(totalMatch[1], 10);
      }
    }

    // Build headers preview for technical transparency
    const headersPreview: Record<string, string> = {
      'content-type': contentType,
      'status': `${response.status} ${response.statusText}`,
      'accept-ranges': acceptRanges ? 'bytes' : 'none',
    };
    if (contentLengthHeader) headersPreview['content-length'] = contentLengthHeader;
    if (response.headers.get('server')) headersPreview['server'] = response.headers.get('server')!;

    // CASE A: Direct Media Stream (video/*, audio/*, application/ogg, application/x-mpegURL)
    const isDirectMedia =
      contentType.startsWith('video/') ||
      contentType.startsWith('audio/') ||
      contentType.includes('application/ogg') ||
      contentType.includes('application/vnd.apple.mpegurl');

    if (isDirectMedia) {
      const filename = extractFilename(parsedUrl, contentDisposition);
      const ext = filename.split('.').pop()?.toLowerCase() || 'mp4';

      const format: VideoFormat = {
        id: 'direct-original',
        format: ext,
        qualityLabel: 'Original Stream / Source Quality',
        mimeType: contentType,
        sizeBytes: sizeBytes,
        formattedSize: formatBytes(sizeBytes),
        directUrl: response.url || parsedUrl.toString(),
        downloadProxyUrl: `/api/download?url=${encodeURIComponent(response.url || parsedUrl.toString())}&filename=${encodeURIComponent(filename)}`,
        isPlayableDirectly: contentType.startsWith('video/'),
      };

      const result: VideoMetadata = {
        originalUrl: rawUrl,
        canonicalUrl: response.url || parsedUrl.toString(),
        domain: parsedUrl.hostname,
        title: filename,
        description: `Direct media stream dari server ${parsedUrl.hostname}`,
        sourceType: 'direct_stream',
        formats: [format],
        technicalDetails: {
          contentType,
          contentLength: sizeBytes,
          acceptRanges,
          server: response.headers.get('server') || 'Unknown',
          protocol: parsedUrl.protocol.replace(':', '').toUpperCase(),
          analyzedAt: new Date().toISOString(),
          statusCode: response.status,
          responseHeadersPreview: headersPreview,
        },
      };

      return {
        status: 'success',
        data: result,
      };
    }

    // CASE B: Webpage HTML with embedded Video / OpenGraph
    if (contentType.includes('text/html')) {
      const htmlController = new AbortController();
      const htmlTimeout = setTimeout(() => htmlController.abort(), 10000);

      const htmlResponse = await fetch(parsedUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: htmlController.signal,
      });
      clearTimeout(htmlTimeout);

      if (!htmlResponse.ok) {
        return {
          status: 'error',
          errorCode: 'NETWORK_ERROR',
          message: `Gagal mengambil halaman HTML: HTTP ${htmlResponse.status}`,
        };
      }

      // Read max 2MB of HTML to avoid memory exhaustion
      const htmlText = await htmlResponse.text();
      const extracted = parseHtmlMedia(htmlText, parsedUrl);

      if (!extracted.foundVideoUrl) {
        return {
          status: 'error',
          errorCode: 'NO_MEDIA_FOUND',
          message: 'Tidak ditemukan elemen video publik yang dapat diakses langsung pada halaman ini.',
          technicalDetails: 'Halaman HTML berhasil dianalisis tetapi tidak mengandung tag <video>, <source>, atau meta og:video publik.',
          legalNotice: 'Jika video memerlukan JavaScript client-side khusus, iframe proteksi pihak ketiga, atau DRM, backend tidak memprosesnya.',
          suggestion: 'Pastikan URL mengarah langsung ke video atau halaman dengan tag HTML5 video publik.',
        };
      }

      // Check the extracted video source to get real headers/size
      let extractedSize: number | undefined;
      let extractedType = 'video/mp4';
      try {
        const headCheck = await fetch(extracted.foundVideoUrl, {
          method: 'HEAD',
          headers: { 'User-Agent': 'Mozilla/5.0' },
        });
        if (headCheck.ok) {
          extractedType = headCheck.headers.get('content-type') || extractedType;
          const len = headCheck.headers.get('content-length');
          if (len) extractedSize = parseInt(len, 10);
        }
      } catch {
        // Fallback to defaults if HEAD to source fails
      }

      const videoExt = extracted.foundVideoUrl.split('.').pop()?.split('?')[0].toLowerCase() || 'mp4';
      const cleanFilename = `${extracted.title.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 50)}.${videoExt}`;

      const format: VideoFormat = {
        id: 'extracted-web-format',
        format: videoExt,
        qualityLabel: 'Web Source Stream',
        mimeType: extractedType,
        sizeBytes: extractedSize,
        formattedSize: formatBytes(extractedSize),
        directUrl: extracted.foundVideoUrl,
        downloadProxyUrl: `/api/download?url=${encodeURIComponent(extracted.foundVideoUrl)}&filename=${encodeURIComponent(cleanFilename)}`,
        isPlayableDirectly: true,
      };

      const result: VideoMetadata = {
        originalUrl: rawUrl,
        canonicalUrl: parsedUrl.toString(),
        domain: parsedUrl.hostname,
        title: extracted.title,
        description: extracted.description,
        thumbnailUrl: extracted.thumbnailUrl,
        sourceType: extracted.sourceType,
        formats: [format],
        technicalDetails: {
          contentType: extractedType,
          contentLength: extractedSize,
          acceptRanges: true,
          server: response.headers.get('server') || 'Web Server',
          protocol: parsedUrl.protocol.replace(':', '').toUpperCase(),
          analyzedAt: new Date().toISOString(),
          statusCode: response.status,
          responseHeadersPreview: headersPreview,
        },
      };

      return {
        status: 'success',
        data: result,
      };
    }

    return {
      status: 'error',
      errorCode: 'UNSUPPORTED_PROTOCOL',
      message: `Tipe konten '${contentType}' bukan format video yang didukung.`,
      technicalDetails: `Server mengembalikan Content-Type: ${contentType}`,
      suggestion: 'Masukkan URL yang mengarah ke file video langsung (.mp4, .webm, dll) atau halaman web publik ber-HTML5 video.',
    };
  } catch (err: unknown) {
    const errorObj = err as Error;
    if (errorObj?.name === 'AbortError') {
      return {
        status: 'error',
        errorCode: 'TIMEOUT',
        message: 'Koneksi ke URL target melebihi batas waktu (Timeout 10 detik).',
        technicalDetails: 'Server target tidak merespons dalam durasi 10.000 ms.',
      };
    }

    return {
      status: 'error',
      errorCode: 'NETWORK_ERROR',
      message: 'Gagal menghubungi server target. Periksa kembali URL yang dimasukkan.',
      technicalDetails: errorObj?.message || 'Unknown network error',
    };
  }
}

// Simple regex parser for HTML media metadata
function parseHtmlMedia(
  html: string,
  baseUrl: URL
): {
  title: string;
  description?: string;
  thumbnailUrl?: string;
  foundVideoUrl?: string;
  sourceType: 'html5_video' | 'opengraph_meta' | 'open_archive';
} {
  // Extract Title
  let title = 'Video Web';
  const ogTitleMatch = html.match(/<meta\s+property=["']og:title["']\s+content=["'](.*?)["']/i);
  const titleTagMatch = html.match(/<title>(.*?)<\/title>/i);
  if (ogTitleMatch && ogTitleMatch[1]) {
    title = ogTitleMatch[1].trim();
  } else if (titleTagMatch && titleTagMatch[1]) {
    title = titleTagMatch[1].trim();
  }

  // Extract Description
  let description: string | undefined;
  const ogDescMatch = html.match(/<meta\s+property=["']og:description["']\s+content=["'](.*?)["']/i);
  if (ogDescMatch && ogDescMatch[1]) {
    description = ogDescMatch[1].trim();
  }

  // Extract Thumbnail
  let thumbnailUrl: string | undefined;
  const ogImageMatch = html.match(/<meta\s+property=["']og:image["']\s+content=["'](.*?)["']/i);
  if (ogImageMatch && ogImageMatch[1]) {
    thumbnailUrl = resolveUrl(ogImageMatch[1].trim(), baseUrl);
  }

  // 1. Look for OpenGraph Video
  const ogVideoMatch =
    html.match(/<meta\s+property=["']og:video["']\s+content=["'](.*?)["']/i) ||
    html.match(/<meta\s+property=["']og:video:url["']\s+content=["'](.*?)["']/i) ||
    html.match(/<meta\s+property=["']og:video:secure_url["']\s+content=["'](.*?)["']/i);

  if (ogVideoMatch && ogVideoMatch[1]) {
    const candidate = resolveUrl(ogVideoMatch[1].trim(), baseUrl);
    if (candidate && !candidate.endsWith('.html')) {
      return {
        title,
        description,
        thumbnailUrl,
        foundVideoUrl: candidate,
        sourceType: 'opengraph_meta',
      };
    }
  }

  // 2. Look for HTML5 <video src="..."> or <source src="...">
  const videoSrcMatch =
    html.match(/<video[^>]+src=["']([^"']+)["']/i) ||
    html.match(/<source[^>]+src=["']([^"']+\.(?:mp4|webm|ogg|mov|m4v))["']/i) ||
    html.match(/<source[^>]+type=["']video\/[^"']+["'][^>]+src=["']([^"']+)["']/i) ||
    html.match(/<source[^>]+src=["']([^"']+)["'][^>]+type=["']video\/[^"']+["']/i);

  if (videoSrcMatch && videoSrcMatch[1]) {
    const candidate = resolveUrl(videoSrcMatch[1].trim(), baseUrl);
    return {
      title,
      description,
      thumbnailUrl,
      foundVideoUrl: candidate,
      sourceType: 'html5_video',
    };
  }

  return {
    title,
    description,
    thumbnailUrl,
    foundVideoUrl: undefined,
    sourceType: 'html5_video',
  };
}

function resolveUrl(urlStr: string, base: URL): string {
  try {
    return new URL(urlStr, base).toString();
  } catch {
    return urlStr;
  }
}
