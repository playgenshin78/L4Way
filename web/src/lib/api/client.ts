import { randomId } from "@/lib/utils";
import type { ApiErrorBody, ApiSuccess } from "./types";
import { mockFetch } from "./mock/adapter";

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api/v1";

/**
 * Mock 开关：仅开发环境默认开启；生产构建必须显式设置
 * VITE_USE_MOCK=true 才会启用，避免生产意外退回 Mock 数据。
 */
const envMock = import.meta.env.VITE_USE_MOCK as string | undefined;
const USE_MOCK = envMock !== undefined ? envMock === "true" : import.meta.env.DEV;

const friendlyErrorMessages: Record<string, string> = {
  backup_not_configured: "尚未配置备份目录",
  backup_not_found: "还没有可下载的备份",
  cluster_plan_not_configured: "节点网络尚未完成初始化",
  csrf_mismatch: "页面状态已过期，请刷新后重试",
  forbidden: "当前账号没有执行此操作的权限",
  internal_error: "操作暂时无法完成，请稍后重试",
  invalid_credentials: "用户名或密码错误",
  invalid_csrf: "页面状态已过期，请刷新后重试",
  invalid_password: "密码不符合要求，请检查长度和复杂度",
  login_busy: "登录请求较多，请稍后再试",
  login_rate_limited: "尝试次数过多，请稍后再试",
  node_already_enrolled: "该节点已经接入，不能重复生成安装命令",
  node_delete_conflict: "该节点已经连接过，不能直接删除",
  node_install_not_configured: "尚未配置节点接入地址",
  node_revoked: "该节点身份已被吊销，不能重新接入",
  not_editable: "此转发由外部配置管理，不能在网页中编辑",
  not_found: "请求的内容不存在或已被删除",
  resource_conflict: "数据已发生变化，请刷新后重试",
  unauthenticated: "登录已过期，请重新登录",
};

function friendlyApiMessage(code: string, backendMessage: string | undefined, status: number): string {
  if (friendlyErrorMessages[code]) return friendlyErrorMessages[code];
  if (backendMessage && /[一-鿿]/.test(backendMessage)) return backendMessage;
  if (code === "invalid_request" || code === "validation_error") return "提交内容有误，请检查后重试";
  if (status >= 500) return "服务暂时不可用，请稍后重试";
  return `请求失败（${status || "网络错误"}）`;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }

  get isUnauthorized() {
    return this.status === 401;
  }
  get isForbidden() {
    return this.status === 403;
  }
  get isNotFound() {
    return this.status === 404;
  }
  get isConflict() {
    return this.status === 409;
  }
  get isRateLimited() {
    return this.status === 429;
  }
}

/* ------------------------------ 内存 CSRF ------------------------------ */
// CSRF token 只来自 login / /auth/me 响应体，仅存内存，刷新后由 /auth/me 恢复。
let csrfToken = "";

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function getCsrfToken(): string {
  return csrfToken;
}

/* ------------------------------ 401 处理 ------------------------------- */
let unauthorizedHandler: (() => void) | null = null;

/** 由认证层注册：任何请求返回 401 时清理会话并跳转登录页 */
export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

/* ---------------------------- 可注入 fetcher ---------------------------- */
type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
let fetcher: Fetcher = USE_MOCK ? mockFetch : (input, init) => fetch(input, init);

/** 测试专用：包装/替换底层 fetcher 以断言 credentials 与请求头 */
export function __setFetcherForTest(fn: Fetcher | null) {
  fetcher = fn ?? (USE_MOCK ? mockFetch : (input, init) => fetch(input, init));
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  idempotencyKey?: string;
  signal?: AbortSignal;
  /** 跳过全局 401 处理（login /auth/me 自身） */
  skipUnauthorizedHandler?: boolean;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, headers = {}, idempotencyKey, signal, skipUnauthorizedHandler } = options;

  const finalHeaders: Record<string, string> = { ...headers };
  if (body !== undefined) finalHeaders["Content-Type"] = "application/json";
  if (method !== "GET") {
    finalHeaders["X-CSRF-Token"] = getCsrfToken();
  }
  if (idempotencyKey) {
    finalHeaders["Idempotency-Key"] = idempotencyKey;
  }

  let res: Response;
  try {
    res = await fetcher(`${API_BASE}${path}`, {
      method,
      headers: finalHeaders,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: "include",
      signal,
    });
  } catch {
    throw new ApiError(0, "service_unavailable", "服务不可用，请检查网络或稍后重试");
  }

  if (res.status === 401 && !skipUnauthorizedHandler) {
    unauthorizedHandler?.();
  }

  let payload: unknown = null;
  try {
    payload = await res.json();
  } catch {
    /* 非 JSON 响应 */
  }

  if (!res.ok) {
    const errBody = payload as ApiErrorBody | null;
    const code = errBody?.error?.code ?? "unknown_error";
    throw new ApiError(
      res.status,
      code,
      friendlyApiMessage(code, errBody?.error?.message, res.status),
    );
  }

  if (res.status === 204) return undefined as T;
  return (payload as ApiSuccess<T>).data;
}

export interface DownloadedFile {
  blob: Blob;
  filename: string;
}

export async function requestDownload(path: string, fallbackFilename: string): Promise<DownloadedFile> {
  let res: Response;
  try {
    res = await fetcher(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "X-CSRF-Token": getCsrfToken() },
      credentials: "include",
    });
  } catch {
    throw new ApiError(0, "service_unavailable", "服务不可用，请检查网络或稍后重试");
  }

  if (res.status === 401) unauthorizedHandler?.();
  if (!res.ok) {
    let payload: ApiErrorBody | null = null;
    try {
      payload = (await res.json()) as ApiErrorBody;
    } catch {
      // 非 JSON 错误响应。
    }
    const code = payload?.error?.code ?? "unknown_error";
    throw new ApiError(
      res.status,
      code,
      friendlyApiMessage(code, payload?.error?.message, res.status),
    );
  }

  const disposition = res.headers.get("Content-Disposition") ?? "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plain = disposition.match(/filename="?([^";]+)"?/i)?.[1];
  let filename = fallbackFilename;
  try {
    filename = decodeURIComponent(encoded ?? plain ?? fallbackFilename);
  } catch {
    filename = plain ?? fallbackFilename;
  }
  filename = filename.replace(/[\\/]/g, "_");
  return { blob: await res.blob(), filename };
}

/** 创建类写操作的幂等键（重复提交复用同一键，避免重复创建） */
export function makeIdempotencyKey(): string {
  return randomId();
}

export const apiConfig = { API_BASE, USE_MOCK };
