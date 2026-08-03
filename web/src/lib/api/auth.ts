import { request } from "./client";
import type { LoginRequest, SessionPayload } from "./types";

function normalizeSession(payload: SessionPayload): SessionPayload {
  return {
    ...payload,
    account: { ...payload.account, tenant_id: payload.account.tenant_id ?? null },
  };
}

export async function login(input: LoginRequest) {
  return normalizeSession(await request<SessionPayload>("/auth/login", {
    method: "POST",
    body: input,
    skipUnauthorizedHandler: true,
  }));
}

export function logout() {
  return request<void>("/auth/logout", { method: "POST", body: {} });
}

export async function me() {
  return normalizeSession(await request<SessionPayload>("/auth/me", { skipUnauthorizedHandler: true }));
}
