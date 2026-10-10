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

// ---------------------------------------------------------------------------
// 添加条目（M9-1）：三来源两段式（预览 → 决策 → 提交），密钥不回传前端
// ---------------------------------------------------------------------------

/** 添加来源：粘贴文本 / 手填表单 / 图片文件（Base64 字节）。 */
export type AddSource =
  | { kind: "text"; text: string }
  | {
      kind: "manual";
      issuer: string;
      account: string;
      secret: string;
      algorithm?: string;
      digits?: number;
      period?: number;
      tags?: string[];
    }
  | { kind: "image"; bytes_b64: string };

/** 单条预览（不含密钥）。conflict：同标识不同密钥，须用户决策；duplicate：同标识同密钥，将自动跳过。 */
export interface AddItemView {
  index: number;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
  tags: string[];
  conflict: boolean;
  duplicate: boolean;
}

/** 预览视图：token 提交时回传校验；failed 为解析失败行；migration_used 提示删除原始迁移二维码。 */
export interface AddPreview {
  token: number;
  items: AddItemView[];
  failed: { line: number; error: string }[];
  notes: string[];
  migration_used: boolean;
}

/** 冲突决策。 */
export type AddDecision = { index: number; action: "overwrite" | "keep_both" };

/** 提交摘要。 */
export interface AddSummary {
  added: number;
  replaced: number;
  kept_both: number;
  skipped_dup: number;
  changed: boolean;
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
  addPreview: (source: AddSource) => invoke<AddPreview>("add_preview", { source }),
  addCommit: (token: number, decisions: AddDecision[]) =>
    invoke<AddSummary>("add_commit", { token, decisions }),
};
