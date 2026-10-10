import { FormEvent, useState } from "react";
import { useSession } from "../store";

/** 解锁屏：主密码输入（type=password，不进任何日志/持久化），失败展示中文错误。 */
export default function UnlockScreen() {
  const unlock = useSession((s) => s.unlock);
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const [password, setPassword] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!password || busy) return;
    // 调用后立刻清空组件内的密码明文（无论成败）
    const pw = password;
    setPassword("");
    void unlock(pw);
  };

  return (
    <section className="unlock">
      <h1>2FA 验证器</h1>
      <p className="hint">输入主密码解锁本地保险库</p>
      <form onSubmit={submit}>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="主密码"
          autoFocus
          autoComplete="current-password"
          aria-label="主密码"
        />
        <button type="submit" disabled={busy || !password}>
          {busy ? "解锁中…" : "解锁"}
        </button>
      </form>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
