export interface VideoFormat {
  id: string;
  format: string;
  qualityLabel: string;
  mimeType: string;
  sizeBytes?: number;
  formattedSize?: string;
  directUrl: string;
  downloadProxyUrl: string;
  isPlayableDirectly: boolean;
}

export type MediaSourceType = 
  | 'direct_stream' 
  | 'html5_video' 
  | 'opengraph_meta' 
  | 'open_archive';

export interface VideoMetadata {
  originalUrl: string;
  canonicalUrl: string;
  domain: string;
  title: string;
  description?: string;
  author?: string;
  thumbnailUrl?: string;
  sourceType: MediaSourceType;
  durationSeconds?: number;
  formats: VideoFormat[];
  technicalDetails: {
    contentType: string;
    contentLength?: number;
    acceptRanges: boolean;
    server?: string;
    protocol: string;
    analyzedAt: string;
    statusCode: number;
    responseHeadersPreview: Record<string, string>;
  };
}

export type AnalyzerErrorCode =
  | 'INVALID_URL'
  | 'SSRF_BLOCKED'
  | 'DRM_PROTECTED'
  | 'AUTH_REQUIRED'
  | 'STREAMING_ENCRYPTED'
  | 'UNSUPPORTED_PROTOCOL'
  | 'NO_MEDIA_FOUND'
  | 'NETWORK_ERROR'
  | 'TIMEOUT'
  | 'UNKNOWN_ERROR';

export interface AnalyzeSuccessResponse {
  status: 'success';
  data: VideoMetadata;
}

export interface AnalyzeErrorResponse {
  status: 'error';
  errorCode: AnalyzerErrorCode;
  message: string;
  technicalDetails?: string;
  legalNotice?: string;
  suggestion?: string;
}

export type AnalyzeApiResponse = AnalyzeSuccessResponse | AnalyzeErrorResponse;
