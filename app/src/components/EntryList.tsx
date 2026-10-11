import { useEffect, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { EntryView } from "../api";
import { findMatches } from "../search";
import { useSession } from "../store";
import AddDialog from "./AddDialog";
import BackupDialog from "./BackupDialog";
import EditDialog from "./EditDialog";
import PasswordDialog from "./PasswordDialog";
import PlainExportDialog from "./PlainExportDialog";
import RecoverDialog from "./RecoverDialog";
import ShowSecretDialog from "./ShowSecretDialog";
import StatusDialog from "./StatusDialog";

const TICK_MS = 1000;
const IDLE_CHECK_MS = 30_000;

/** 单行条目：服务商、账号、验证码（可复制，30 秒后自动清除剪贴板）、剩余秒数、编辑/删除。 */
function EntryRow({
  entry,
  onCopy,
  onShowSecret,
  onEdit,
  onDelete,
}: {
  entry: EntryView;
  onCopy: (prefix: string) => void;
  onShowSecret: (entry: EntryView) => void;
  onEdit: (entry: EntryView) => void;
  onDelete: (entry: EntryView) => void;
}) {
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
      <td className="row-actions">
        <button
          type="button"
          className="ghost"
          onClick={() => onShowSecret(entry)}
          title="查看密钥（明文，需确认）"
        >
          密钥
        </button>
        <button type="button" className="ghost" onClick={() => onEdit(entry)} title="编辑条目">
          编辑
        </button>
        <button type="button" className="ghost" onClick={() => onDelete(entry)} title="删除条目">
          删除
        </button>
      </td>
    </tr>
  );
}

/** 删除二次确认：展示条目标识与不可恢复警示（需点击确认，不设密码门槛——
 * 主密码已在会话内，文件级回退依赖加密备份）。 */
function DeleteConfirm({
  entry,
  busy,
  onConfirm,
  onCancel,
}: {
  entry: EntryView;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="modal-mask">
      <div className="modal">
        <h1>确认删除</h1>
        <p>
          将删除条目 <strong>{entry.issuer} / {entry.account}</strong>
          （ID 前缀 {entry.id_prefix}）。
        </p>
        <p className="warn">删除不可恢复（除非事先做过加密备份），请确认。</p>
        <div className="actions">
          <button type="button" onClick={onCancel} disabled={busy}>
            取消
          </button>
          <button type="button" className="danger" onClick={onConfirm} disabled={busy}>
            {busy ? "删除中…" : "确认删除"}
          </button>
        </div>
      </div>
    </div>
  );
}

/** 条目列表页：每秒 tick 刷新（周期边界回后端切换验证码），30 秒心跳触发后端空闲超时判定；
 * 搜索框实时过滤（与 CLI find 同语义），行内编辑 / 删除；工具栏承担导入导出（M9-3）。 */
export default function EntryList() {
  const entries = useSession((s) => s.entries);
  const vaultPath = useSession((s) => s.vaultPath);
  const notice = useSession((s) => s.notice);
  const busy = useSession((s) => s.busy);
  const lock = useSession((s) => s.lock);
  const tick = useSession((s) => s.tick);
  const checkIdle = useSession((s) => s.checkIdle);
  const copyCode = useSession((s) => s.copyCode);
  const deleteEntry = useSession((s) => s.deleteEntry);
  const exportBackup = useSession((s) => s.exportBackup);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<EntryView | null>(null);
  const [deleting, setDeleting] = useState<EntryView | null>(null);
  const [showingSecret, setShowingSecret] = useState<EntryView | null>(null);
  const [importingBackup, setImportingBackup] = useState(false);
  const [exportingPlain, setExportingPlain] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [showingStatus, setShowingStatus] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    const id = window.setInterval(() => tick(), TICK_MS);
    return () => window.clearInterval(id);
  }, [tick]);

  useEffect(() => {
    const id = window.setInterval(() => void checkIdle(), IDLE_CHECK_MS);
    return () => window.clearInterval(id);
  }, [checkIdle]);

  const visible = findMatches(entries, query);

  // 导出加密备份：系统另存对话框给出显式路径（字节级拷贝，无需门槛——
  // 输出仍是加密文件，安全性不低于保险库本体）
  const doExportBackup = async () => {
    const path = await save({
      title: "导出加密备份",
      defaultPath: "vault-backup.json",
      filters: [{ name: "2FA 加密备份", extensions: ["json"] }],
    });
    if (path !== null) void exportBackup(path);
  };

  return (
    <section className="list">
      <header>
        <h1>2FA 验证器</h1>
        <div className="header-actions">
          <button type="button" onClick={() => setAdding(true)}>
            添加条目
          </button>
          <button type="button" onClick={() => setImportingBackup(true)} title="从加密备份恢复（覆盖当前库）">
            导入备份
          </button>
          <button type="button" onClick={() => void doExportBackup()} title="导出加密备份（字节级拷贝）">
            导出备份
          </button>
          <button
            type="button"
            className="danger-ghost"
            onClick={() => setExportingPlain(true)}
            title="明文导出（危险：未加密，四道门槛）"
          >
            明文导出
          </button>
          <button type="button" onClick={() => setChangingPassword(true)} title="修改主密码（旧密码验证）">
            改密码
          </button>
          <button type="button" onClick={() => setRecovering(true)} title="恢复码恢复（强制轮换，旧码作废）">
            恢复码
          </button>
          <button type="button" onClick={() => setShowingStatus(true)} title="路径 / 来源 / 条目数 / KDF 版本">
            状态
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
      {importingBackup && <BackupDialog onClose={() => setImportingBackup(false)} />}
      {exportingPlain && <PlainExportDialog onClose={() => setExportingPlain(false)} />}
      {changingPassword && <PasswordDialog onClose={() => setChangingPassword(false)} />}
      {recovering && <RecoverDialog onClose={() => setRecovering(false)} />}
      {showingStatus && <StatusDialog onClose={() => setShowingStatus(false)} />}
      {editing !== null && <EditDialog entry={editing} onClose={() => setEditing(null)} />}
      {showingSecret !== null && (
        <ShowSecretDialog
          prefix={showingSecret.id_prefix}
          onClose={() => setShowingSecret(null)}
        />
      )}
      {deleting !== null && (
        <DeleteConfirm
          entry={deleting}
          busy={busy}
          onCancel={() => setDeleting(null)}
          onConfirm={() => void deleteEntry(deleting.id_prefix).then(() => setDeleting(null))}
        />
      )}
      {entries.length === 0 ? (
        <p className="hint">保险库为空，点「添加条目」开始。</p>
      ) : (
        <>
          <input
            className="search"
            type="search"
            placeholder="搜索服务商 / 账号 / 标签"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="搜索条目"
          />
          {visible.length === 0 ? (
            <p className="hint">没有匹配「{query}」的条目。</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>服务商 / 账号</th>
                  <th>验证码</th>
                  <th>剩余</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((entry) => (
                  <EntryRow
                    key={entry.id}
                    entry={entry}
                    onCopy={(prefix) => void copyCode(prefix)}
                    onShowSecret={setShowingSecret}
                    onEdit={setEditing}
                    onDelete={setDeleting}
                  />
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
