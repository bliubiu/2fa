import { create } from "zustand";
import { api, EntryView, error_message } from "./api";

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

  unlock(password: string): Promise<void>;
  lock(): Promise<void>;
  /** 心跳（30 秒一次）：后端空闲超时则自动锁定，前端回解锁屏。 */
  checkIdle(): Promise<void>;
  /** 复制验证码：后端写入剪贴板并安排 30 秒自动清除。 */
  copyCode(prefix: string): Promise<void>;
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
      set({ status: "locked", entries: [], error: null, notice: null });
    }
  },

  async checkIdle() {
    try {
      if (await api.checkIdle()) {
        set({
          status: "locked",
          entries: [],
          notice: null,
          error: "空闲超时，已自动锁定（密钥已归零）",
        });
      }
    } catch (err) {
      // 心跳失败通常意味着会话已被后端锁定：回解锁屏
      set({ status: "locked", entries: [], notice: null, error: error_message(err) });
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

  async refresh() {
    if (get().status !== "unlocked") return;
    try {
      set({ entries: await api.listEntries() });
    } catch (err) {
      // 刷新失败最常见的情形是会话已被后端锁定（如空闲超时）：回解锁屏
      set({ status: "locked", entries: [], notice: null, error: error_message(err) });
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
