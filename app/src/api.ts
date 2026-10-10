import { invoke } from "@tauri-apps/api/core";

// 与 Rust 侧 commands 的视图结构一一对应（snake_case 由 serde 序列化保留）
export interface EntryView {
  id: string;
  id_prefix: string;
  issuer: string;
  account: string;
  /** 当前验证码；密钥解码失败时为 null（界面显示「错误」）。 */
  code: string | null;
  remaining_secs: number;
  algorithm: string;
  digits: number;
  period: number;
  tags: string[];
}

export interface StatusView {
  path: string;
  source: string;
  unlocked: boolean;
  entry_count: number | null;
  kdf_versions: string | null;
}

export interface AppError {
  kind: string;
  message: string;
}

/** 提取后端结构化错误（{ kind, message }）的中文消息；其余归为未知错误。 */
export function error_message(err: unknown): string {
  if (typeof err === "object" && err !== null && "kind" in err && "message" in err) {
    return String((err as AppError).message);
  }
  return "发生未知错误，请重试";
}

/** 后端命令的类型化封装：前端不出现裸 invoke 字符串。 */
export const api = {
  unlock: (password: string) => invoke<{ entry_count: number }>("unlock", { password }),
  lock: () => invoke<boolean>("lock"),
  checkIdle: () => invoke<boolean>("check_idle"),
  status: () => invoke<StatusView>("status"),
  listEntries: () => invoke<EntryView[]>("list_entries"),
  copyCode: (prefix: string) => invoke<void>("copy_code", { prefix }),
};
