import { FormEvent, useState } from "react";
import { useSession } from "../store";

/** 恢复码恢复与强制轮换（M9-4）：输入当前恢复码 → 后端验证并生成新恢复码
 * （旧码即刻作废）→ **强制**展示新恢复码并要求确认已保存（唯一出口是
 * 「我已保存」，新码只显示这一次，跳过即无法关闭）。恢复码通道不解锁
 * 会话——恢复完成后仍需主密码或新恢复码解锁（CLI `recover` 同语义）。 */
export default function RecoverDialog({ onClose }: { onClose: () => void }) {
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const recover = useSession((s) => s.recover);
  const [oldCode, setOldCode] = useState("");
  const [newCode, setNewCode] = useState<string | null>(null);

  // 新码已生成：强制确认态——没有「关闭」按钮，只有「我已保存」
  if (newCode !== null) {
    return (
      <div className="modal-mask">
        <div className="modal">
          <h1>新恢复码（只显示这一次）</h1>
          <p className="hint">丢失主密码时的唯一恢复手段，请抄写到纸上妥善保存，不要存入联网设备。</p>
          <p className="recovery-code">{newCode}</p>
          <p className="warn">旧恢复码已即刻作废；未确认保存前本窗口无法关闭。</p>
          <div className="actions">
            <button type="button" onClick={onClose}>
              我已保存
            </button>
          </div>
        </div>
      </div>
    );
  }

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!oldCode.trim() || busy) return;
    const code = oldCode;
    setOldCode("");
    void recover(code)
      .then(setNewCode)
      .catch(() => undefined);
  };

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>恢复码恢复</h1>
          <button type="button" className="ghost" onClick={onClose} disabled={busy}>
            关闭
          </button>
        </header>
        <form className="plain-form" onSubmit={submit}>
          <p className="hint">
            忘记主密码时，输入当前恢复码即可完成找回。恢复成功后旧恢复码将<b>强制轮换</b>
            （即刻作废），届时会展示只显示一次的新恢复码。本操作不会解锁保险库。
          </p>
          <label>
            当前恢复码
            <input
              type="text"
              value={oldCode}
              onChange={(e) => setOldCode(e.target.value)}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
              placeholder="XXXX-XXXX-XXXX-XXXX"
              aria-label="当前恢复码"
            />
          </label>
          <div className="actions">
            <button type="button" onClick={onClose} disabled={busy}>
              取消
            </button>
            <button type="submit" disabled={busy || oldCode.trim().length === 0}>
              {busy ? "轮换中…" : "轮换并获取新恢复码"}
            </button>
          </div>
        </form>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
