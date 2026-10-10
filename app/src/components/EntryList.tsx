import { useEffect } from "react";
import { EntryView } from "../api";
import { useSession } from "../store";

const TICK_MS = 1000;

/** 单行条目：服务商、账号、验证码、剩余秒数——与 CLI list 输出逐条一致。 */
function EntryRow({ entry }: { entry: EntryView }) {
  const progress = Math.round((entry.remaining_secs / entry.period) * 100);
  return (
    <tr>
      <td>
        {entry.issuer}
        <div className="account">{entry.account}</div>
      </td>
      <td>
        <span className={`code${entry.code === null ? " code-error" : ""}`}>
          {entry.code ?? "错误"}
        </span>
        <div className="period-bar" aria-hidden>
          <div className="period-fill" style={{ width: `${progress}%` }} />
        </div>
      </td>
      <td className="remaining">{entry.remaining_secs}s</td>
    </tr>
  );
}

/** 条目列表页：每秒 tick 刷新，周期边界由 store 回后端切换验证码。 */
export default function EntryList() {
  const entries = useSession((s) => s.entries);
  const vaultPath = useSession((s) => s.vaultPath);
  const lock = useSession((s) => s.lock);
  const tick = useSession((s) => s.tick);

  useEffect(() => {
    const id = window.setInterval(() => tick(), TICK_MS);
    return () => window.clearInterval(id);
  }, [tick]);

  return (
    <section className="list">
      <header>
        <h1>2FA 验证器</h1>
        <button type="button" onClick={() => void lock()}>
          锁定
        </button>
      </header>
      <p className="vault-path" title="当前保险库">
        保险库：{vaultPath}
      </p>
      {entries.length === 0 ? (
        <p className="hint">保险库为空，可先用 CLI 的 add / import 添加条目（M9 提供 GUI 入口）。</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>服务商 / 账号</th>
              <th>验证码</th>
              <th>剩余</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <EntryRow key={entry.id} entry={entry} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
