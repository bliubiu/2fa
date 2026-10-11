import { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { ExportOut } from "../api";
import { useSession } from "../store";

/** 明文导出（危险出口，M9-3）：四道门槛 GUI 化——
 * 1. 输入当前条目数二次确认（后端校验，与 CLI 输入条目数同语义）
 * 2. 系统另存对话框显式选择输出路径（无默认路径）
 * 3. 文件首行中文警告注释（core 序列化器写入）
 * 4. 完成后强提示删除（完成态常驻弹窗，用户确认后才关闭） */
export default function PlainExportDialog({ onClose }: { onClose: () => void }) {
  const entries = useSession((s) => s.entries);
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const exportPlain = useSession((s) => s.exportPlain);
  const [confirmCount, setConfirmCount] = useState("");
  const [done, setDone] = useState<ExportOut | null>(null);

  // 门槛 1 前端预校验（后端仍为准）：数字且与当前条目数一致
  const count = entries.length;
  const confirmed = confirmCount.trim() === String(count);

  // 门槛 2：系统另存对话框给出显式路径后执行导出
  const run = async () => {
    const path = await save({
      title: "明文导出（危险：未加密）",
      defaultPath: "2fa-明文导出.txt",
      filters: [{ name: "otpauth 文本", extensions: ["txt"] }],
    });
    if (path === null) return; // 用户取消
    const out = await exportPlain(path, confirmCount).catch(() => undefined);
    if (out !== undefined) setDone(out);
  };

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>明文导出（危险）</h1>
          {done === null && (
            <button type="button" className="ghost" onClick={onClose} disabled={busy}>
              关闭
            </button>
          )}
        </header>
        {done === null ? (
          <div className="plain-form">
            <p className="warn">
              明文导出将把 <strong>{count}</strong> 个条目的密钥以未加密形式写入磁盘，
              任何人拿到该文件即可生成你的验证码并接管账号。
            </p>
            <label>
              请输入当前条目数（{count}）以确认
              <input
                type="text"
                inputMode="numeric"
                value={confirmCount}
                onChange={(e) => setConfirmCount(e.target.value)}
                disabled={busy}
                autoComplete="off"
                aria-label="确认条目数"
              />
            </label>
            <div className="actions">
              <button type="button" onClick={onClose} disabled={busy}>
                取消
              </button>
              <button
                type="button"
                className="danger"
                disabled={busy || !confirmed}
                onClick={() => void run()}
                title={confirmed ? undefined : "先输入当前条目数"}
              >
                {busy ? "导出中…" : "选择位置并导出"}
              </button>
            </div>
          </div>
        ) : (
          // 门槛 4：完成即强提示删除（无「关闭」以外的出口）
          <div className="plain-done">
            <p>
              明文导出完成：{count} 个条目 → {done.path}（{done.bytes} 字节，标签不包含在
              otpauth URI 中）。
            </p>
            <p className="warn">
              安全提醒：该文件<b>未受任何加密保护</b>，请立即转移到安全位置并尽快删除！
            </p>
            <div className="actions">
              <button type="button" onClick={onClose}>
                我已知晓
              </button>
            </div>
          </div>
        )}
        {error && done === null && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
