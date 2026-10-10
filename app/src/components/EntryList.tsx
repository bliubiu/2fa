import { useEffect, useState } from "react";
import { EntryView } from "../api";
import { useSession } from "../store";
import AddDialog from "./AddDialog";

const TICK_MS = 1000;
const IDLE_CHECK_MS = 30_000;

/** 单行条目：服务商、账号、验证码（可复制，30 秒后自动清除剪贴板）、剩余秒数——与 CLI list 输出逐条一致。 */
function EntryRow({ entry, onCopy }: { entry: EntryView; onCopy: (prefix: string) => void }) {
  const progress = Math.round((entry.remaining_secs / entry.period) * 100);
  return (
    <tr>
      <td>
        {entry.issuer}
        <div className="account">{entry.account}</div>
      </td>
      <td>
        {entry.code === null ? (
          <span className="code code-error">错误</span>
        ) : (
          <button
            type="button"
            className="code-btn"
            title="复制验证码（30 秒后自动清除）"
            onClick={() => onCopy(entry.id_prefix)}
          >
            {entry.code}
          </button>
        )}
        <div className="period-bar" aria-hidden>
          <div className="period-fill" style={{ width: `${progress}%` }} />
        </div>
      </td>
      <td className="remaining">{entry.remaining_secs}s</td>
    </tr>
  );
}

/** 条目列表页：每秒 tick 刷新（周期边界回后端切换验证码），30 秒心跳触发后端空闲超时判定。 */
export default function EntryList() {
  const entries = useSession((s) => s.entries);
  const vaultPath = useSession((s) => s.vaultPath);
  const notice = useSession((s) => s.notice);
  const lock = useSession((s) => s.lock);
  const tick = useSession((s) => s.tick);
  const checkIdle = useSession((s) => s.checkIdle);
  const copyCode = useSession((s) => s.copyCode);
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    const id = window.setInterval(() => tick(), TICK_MS);
    return () => window.clearInterval(id);
  }, [tick]);

  useEffect(() => {
    const id = window.setInterval(() => void checkIdle(), IDLE_CHECK_MS);
    return () => window.clearInterval(id);
  }, [checkIdle]);

  return (
    <section className="list">
      <header>
        <h1>2FA 验证器</h1>
        <div className="header-actions">
          <button type="button" onClick={() => setAdding(true)}>
            添加条目
          </button>
          <button type="button" onClick={() => void lock()}>
            锁定
          </button>
        </div>
      </header>
      <p className="vault-path" title="当前保险库">
        保险库：{vaultPath}
      </p>
      {notice !== null && <p className="notice">{notice}</p>}
      {adding && <AddDialog onClose={() => setAdding(false)} />}
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
              <EntryRow key={entry.id} entry={entry} onCopy={(prefix) => void copyCode(prefix)} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
