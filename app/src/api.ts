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

// ---------------------------------------------------------------------------
// 导入导出（M9-3）：加密备份字节级往返；明文导出为危险出口（四道门槛）
// ---------------------------------------------------------------------------

/** 导出结果（加密备份与明文导出共用）。 */
export interface ExportOut {
  /** 导出文件路径（回显——防呆纪律）。 */
  path: string;
  /** 写入字节数。 */
  bytes: number;
}

/** 加密备份导入结果：need_confirm（备份凭据已验证，等待确认覆盖）或 done（已导入，会话已强制锁定）。 */
export type ImportOut =
  | { stage: "need_confirm"; entry_count: number; schema_migrates: boolean }
  | { stage: "done"; entry_count: number };

/** 查看密钥视图（`show` 等价；确认弹窗在前端，密钥仅在确认后回传）。 */
export interface SecretView {
  id: string;
  id_prefix: string;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
  tags: string[];
  code: string | null;
  remaining_secs: number;
  /** 明文密钥（Base32）。 */
  secret: string;
}

// ---------------------------------------------------------------------------
// 编辑与删除（M9-2）：字段级修改（None = 保持不变，secret 提供即整体替换）
// ---------------------------------------------------------------------------

/** 编辑字段（语义对齐 CLI edit）。 */
export interface EditFields {
  issuer?: string;
  account?: string;
  secret?: string;
  algorithm?: string;
  digits?: number;
  period?: number;
  tags?: string[];
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
  editEntry: (prefix: string, fields: EditFields) =>
    invoke<void>("edit_entry", { prefix, fields }),
  deleteEntry: (prefix: string) => invoke<string>("delete_entry", { prefix }),
  exportBackup: (path: string) => invoke<ExportOut>("export_backup", { path }),
  importBackup: (bytesB64: string, password: string, confirmed: boolean) =>
    invoke<ImportOut>("import_backup", { bytesB64, password, confirmed }),
  exportPlain: (path: string, confirmCount: string) =>
    invoke<ExportOut>("export_plain", { path, confirmCount }),
  showEntry: (prefix: string) => invoke<SecretView>("show_entry", { prefix }),
};
