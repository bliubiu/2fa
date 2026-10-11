import { create } from "zustand";
import {
  AddDecision,
  AddPreview,
  AddSource,
  EditFields,
  ExportOut,
  ImportOut,
  api,
  EntryView,
  error_message,
  SecretView,
} from "./api";

/** 前端会话状态机：locked ↔ unlocked。主密码只在解锁调用瞬间存在，不进任何状态、不持久化。 */
interface SessionState {
  status: "locked" | "unlocked";
  /** 展示给用户的中文错误（解锁失败、刷新失败等）。 */
  error: string | null;
  /** 非错误类提示（复制成功等）。 */
  notice: string | null;
  /** 解锁请求进行中（防重复提交）。 */
  busy: boolean;
  /** 保险库绝对路径（status 回显——防呆最后一道防线）。 */
  vaultPath: string;
  /** 条目列表（解锁后加载，每秒本地倒计时 + 周期边界回后端刷新）。 */
  entries: EntryView[];
  /** 添加条目预览（两段式：预览暂存 → 决策提交；不含密钥）。 */
  pending: AddPreview | null;
  /** 加密备份导入确认态（凭据已验证，等待用户确认覆盖）。 */
  importPreview: { entry_count: number; schema_migrates: boolean } | null;
  /** 查看密钥视图（确认弹窗后后端回传；回到锁定态即清空）。 */
  secretView: SecretView | null;

  unlock(password: string): Promise<void>;
  lock(): Promise<void>;
  /** 心跳（30 秒一次）：后端空闲超时则自动锁定，前端回解锁屏。 */
  checkIdle(): Promise<void>;
  /** 复制验证码：后端写入剪贴板并安排 30 秒自动清除。 */
  copyCode(prefix: string): Promise<void>;
  /** 添加条目第一步：解析来源产出预览（后端暂存待提交区）。 */
  previewAdd(source: AddSource): Promise<void>;
  /** 添加条目第二步：按决策提交落盘并刷新列表。 */
  commitAdd(decisions: AddDecision[]): Promise<void>;
  /** 放弃本轮添加（清预览；后端待提交区在下次预览或锁定时清除）。 */
  cancelAdd(): void;
  /** 编辑条目（字段级，密钥留空即不变）并刷新列表。 */
  editEntry(prefix: string, fields: EditFields): Promise<void>;
  /** 删除条目并刷新列表（前端须先二次确认）。 */
  deleteEntry(prefix: string): Promise<void>;
  /** 导出加密备份（字节级拷贝，无需解锁；路径来自系统另存对话框）。 */
  exportBackup(path: string): Promise<void>;
  /** 导入加密备份（两段式）：未确认返回预览，确认后执行覆盖——后端强制锁定
   * 会话（凭据已替换为备份中的），前端随之回解锁屏。返回结果供对话框流转。 */
  importBackup(bytesB64: string, password: string, confirmed: boolean): Promise<ImportOut>;
  /** 放弃本轮备份导入确认（清预览态）。 */
  cancelImport(): void;
  /** 明文导出（危险出口）：门槛 1 条目数由后端校验；返回结果供对话框展示
   * 门槛 4 的删除强提示。 */
  exportPlain(path: string, confirmCount: string): Promise<ExportOut>;
  /** 查看密钥（前端确认弹窗之后调用；密钥进入前端状态，锁定即清空）。 */
  showSecret(prefix: string): Promise<void>;
  /** 关闭查看密钥视图（密钥即刻离开前端状态）。 */
  clearSecretView(): void;
  /** 改主密码（旧密码验证 + 新密码替换；主密钥与条目明文不变，会话保持解锁）。 */
  changePassword(oldPassword: string, newPassword: string): Promise<void>;
  /** 恢复码恢复（强制轮换）：返回新恢复码供对话框强制确认展示；
   * 不解锁会话——恢复完成后仍需主密码或新恢复码解锁。 */
  recover(oldCode: string): Promise<string>;
  /** 从后端全量刷新条目列表。 */
  refresh(): Promise<void>;
  /** 每秒心跳：非边界秒本地递减剩余秒；任一条目到边界（remaining<=1）即回后端取新验证码。 */
  tick(): void;
}

export const useSession = create<SessionState>((set, get) => ({
  status: "locked",
  error: null,
  notice: null,
  busy: false,
  vaultPath: "",
  entries: [],
  pending: null,
  importPreview: null,
  secretView: null,

  async unlock(password) {
    set({ busy: true, error: null });
    try {
      await api.unlock(password);
      const [status, entries] = await Promise.all([api.status(), api.listEntries()]);
      set({ status: "unlocked", busy: false, notice: null, vaultPath: status.path, entries });
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  async lock() {
    try {
      await api.lock();
    } finally {
      set({
        status: "locked",
        entries: [],
        error: null,
        notice: null,
        pending: null,
        importPreview: null,
        secretView: null,
      });
    }
  },

  async checkIdle() {
    try {
      if (await api.checkIdle()) {
        set({
          status: "locked",
          entries: [],
          notice: null,
          importPreview: null,
          secretView: null,
          error: "空闲超时，已自动锁定（密钥已归零）",
        });
      }
    } catch (err) {
      // 心跳失败通常意味着会话已被后端锁定：回解锁屏
      set({ status: "locked", entries: [], notice: null, importPreview: null, secretView: null, error: error_message(err) });
    }
  },

  async copyCode(prefix) {
    try {
      await api.copyCode(prefix);
      set({ notice: "已复制，30 秒后自动清除剪贴板", error: null });
    } catch (err) {
      set({ error: error_message(err), notice: null });
    }
  },

  async previewAdd(source) {
    set({ busy: true, error: null, notice: null });
    try {
      const preview = await api.addPreview(source);
      set({ pending: preview, busy: false });
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  async commitAdd(decisions) {
    const pending = get().pending;
    if (pending === null) return;
    set({ busy: true, error: null });
    try {
      const summary = await api.addCommit(pending.token, decisions);
      set({ pending: null, busy: false });
      const parts: string[] = [];
      if (summary.added > 0) parts.push(`新增 ${summary.added}`);
      if (summary.replaced > 0) parts.push(`覆盖 ${summary.replaced}`);
      if (summary.kept_both > 0) parts.push(`并存 ${summary.kept_both}`);
      if (summary.skipped_dup > 0) parts.push(`跳过重复 ${summary.skipped_dup}`);
      set({ notice: parts.length > 0 ? `添加完成：${parts.join("，")}` : null });
      await get().refresh();
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  cancelAdd() {
    set({ pending: null });
  },

  async editEntry(prefix, fields) {
    set({ busy: true, error: null, notice: null });
    try {
      await api.editEntry(prefix, fields);
      set({ busy: false, notice: "已保存修改" });
      await get().refresh();
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  async deleteEntry(prefix) {
    set({ busy: true, error: null, notice: null });
    try {
      const desc = await api.deleteEntry(prefix);
      set({ busy: false, notice: `已删除条目：${desc}` });
      await get().refresh();
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  async exportBackup(path) {
    set({ busy: true, error: null, notice: null });
    try {
      const out = await api.exportBackup(path);
      set({ busy: false, notice: `加密备份已导出：${out.path}（${out.bytes} 字节，字节级拷贝）` });
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  async importBackup(bytesB64, password, confirmed) {
    set({ busy: true, error: null, notice: null });
    try {
      const out = await api.importBackup(bytesB64, password, confirmed);
      if (out.stage === "need_confirm") {
        set({ busy: false, importPreview: { entry_count: out.entry_count, schema_migrates: out.schema_migrates } });
      } else {
        // 后端已强制锁定会话（凭据被替换为备份中的），前端随之回解锁屏
        set({
          busy: false,
          status: "locked",
          entries: [],
          pending: null,
          importPreview: null,
          secretView: null,
          notice: `已导入 ${out.entry_count} 个条目，请用备份中的主密码重新解锁`,
        });
      }
      return out;
    } catch (err) {
      set({ busy: false, error: error_message(err) });
      throw err;
    }
  },

  cancelImport() {
    set({ importPreview: null });
  },

  async exportPlain(path, confirmCount) {
    set({ busy: true, error: null, notice: null });
    try {
      const out = await api.exportPlain(path, confirmCount);
      set({ busy: false });
      return out;
    } catch (err) {
      set({ busy: false, error: error_message(err) });
      throw err;
    }
  },

  async showSecret(prefix) {
    set({ busy: true, error: null, notice: null });
    try {
      const view = await api.showEntry(prefix);
      set({ busy: false, secretView: view });
    } catch (err) {
      set({ busy: false, error: error_message(err) });
    }
  },

  clearSecretView() {
    set({ secretView: null });
  },

  async changePassword(oldPassword, newPassword) {
    set({ busy: true, error: null, notice: null });
    try {
      await api.changePassword(oldPassword, newPassword);
      set({ busy: false, notice: "主密码已更新，下次解锁请使用新主密码" });
    } catch (err) {
      set({ busy: false, error: error_message(err) });
      throw err;
    }
  },

  async recover(oldCode) {
    set({ busy: true, error: null, notice: null });
    try {
      const newCode = await api.recover(oldCode);
      set({ busy: false });
      return newCode;
    } catch (err) {
      set({ busy: false, error: error_message(err) });
      throw err;
    }
  },

  async refresh() {
    if (get().status !== "unlocked") return;
    try {
      set({ entries: await api.listEntries() });
    } catch (err) {
      // 刷新失败最常见的情形是会话已被后端锁定（如空闲超时）：回解锁屏
      set({
        status: "locked",
        entries: [],
        notice: null,
        importPreview: null,
        secretView: null,
        error: error_message(err),
      });
    }
  },

  tick() {
    const { status, entries, refresh } = get();
    if (status !== "unlocked") return;
    let boundary = false;
    const next = entries.map((entry) => {
      if (entry.remaining_secs <= 1) {
        boundary = true;
        return entry;
      }
      return { ...entry, remaining_secs: entry.remaining_secs - 1 };
    });
    if (boundary) {
      // 周期边界：以后端权威值为准（验证码切换、剩余秒重置）
      void refresh();
    } else {
      set({ entries: next });
    }
  },
}));
