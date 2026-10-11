import { FormEvent, useState } from "react";
import { useSession } from "../store";

/** 改主密码（M9-4）：旧密码验证 + 新密码二次输入（前端预校验一致，后端
 * 再验证旧密码并重写封套）。主密钥与条目明文不变，会话保持解锁。 */
export default function PasswordDialog({ onClose }: { onClose: () => void }) {
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const notice = useSession((s) => s.notice);
  const changePassword = useSession((s) => s.changePassword);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [done, setDone] = useState(false);

  const mismatch = newPw.length > 0 && newPw2.length > 0 && newPw !== newPw2;
  const canSubmit = !busy && oldPw.length > 0 && newPw.length > 0 && !mismatch;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    // 提交后即刻清空组件内全部密码明文（无论成败）
    const oldP = oldPw;
    const newP = newPw;
    setOldPw("");
    setNewPw("");
    setNewPw2("");
    void changePassword(oldP, newP)
      .then(() => setDone(true))
      .catch(() => undefined);
  };

  const close = () => {
    setOldPw("");
    setNewPw("");
    setNewPw2("");
    onClose();
  };

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>修改主密码</h1>
          <button type="button" className="ghost" onClick={close} disabled={busy}>
            关闭
          </button>
        </header>
        {done ? (
          <div>
            <p>{notice}</p>
            <div className="actions">
              <button type="button" onClick={close}>
                好的
              </button>
            </div>
          </div>
        ) : (
          <form className="plain-form" onSubmit={submit}>
            <label>
              当前主密码
              <input
                type="password"
                value={oldPw}
                onChange={(e) => setOldPw(e.target.value)}
                disabled={busy}
                autoComplete="current-password"
              />
            </label>
            <label>
              新主密码
              <input
                type="password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                disabled={busy}
                autoComplete="new-password"
              />
            </label>
            <label>
              再输入一次新主密码
              <input
                type="password"
                value={newPw2}
                onChange={(e) => setNewPw2(e.target.value)}
                disabled={busy}
                autoComplete="new-password"
                aria-invalid={mismatch}
              />
            </label>
            {mismatch && <p className="warn">两次输入的新主密码不一致。</p>}
            <div className="actions">
              <button type="button" onClick={close} disabled={busy}>
                取消
              </button>
              <button type="submit" disabled={!canSubmit}>
                {busy ? "更新中…" : "确认修改"}
              </button>
            </div>
          </form>
        )}
        {error && !done && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
