import { useState } from "react";
import { useSession } from "../store";

/** 导入加密备份（M9-3）：选择备份文件 → 输入备份的主密码 → 只读验证预览 →
 * 确认覆盖。覆盖后当前保险库的条目、主密码与恢复码全部替换为备份中的凭据
 * （后端强制锁定会话，须重新解锁）；覆盖前当前库自动存 `.bak` 作回滚保障。
 * 备份通道无需解锁当前保险库——忘记主密码时的唯一恢复出路。 */
export default function BackupDialog({ onClose }: { onClose: () => void }) {
  const importPreview = useSession((s) => s.importPreview);
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  // 文件字节与密码保存在对话框本地（不进全局状态），确认时回传
  const [bytesB64, setBytesB64] = useState<string | null>(null);
  const [password, setPassword] = useState("");

  const close = () => {
    setBytesB64(null);
    setPassword("");
    onClose();
  };

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>从加密备份恢复</h1>
          <button type="button" className="ghost" onClick={close} disabled={busy}>
            关闭
          </button>
        </header>
        {importPreview === null ? (
          <PickForm
            busy={busy}
            bytesB64={bytesB64}
            onPicked={setBytesB64}
            password={password}
            onPassword={setPassword}
          />
        ) : (
          <ConfirmForm bytesB64={bytesB64} password={password} busy={busy} onClose={close} />
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}

/** 第一步：选择备份文件 + 输入备份的主密码（「验证备份」只读验证，不写盘）。 */
function PickForm({
  busy,
  bytesB64,
  onPicked,
  password,
  onPassword,
}: {
  busy: boolean;
  bytesB64: string | null;
  onPicked: (b64: string | null) => void;
  password: string;
  onPassword: (v: string) => void;
}) {
  const importBackup = useSession((s) => s.importBackup);
  const [fileName, setFileName] = useState<string | null>(null);

  const pick = async (file: File | undefined) => {
    if (!file) {
      onPicked(null);
      setFileName(null);
      return;
    }
    setFileName(file.name);
    // readAsDataURL → data:…;base64,xxxx → 截取 Base64 段（与图片扫码同模式）
    const dataUrl = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(new Error("读取文件失败"));
      reader.readAsDataURL(file);
    });
    onPicked(dataUrl.slice(dataUrl.indexOf(",") + 1));
  };

  const verify = () => {
    if (bytesB64 !== null && password) void importBackup(bytesB64, password, false).catch(() => undefined);
  };

  return (
    <div className="backup-form">
      <p className="hint">
        加密备份是保险库文件的字节级拷贝（CLI <code>export backup</code> 的产物）。
      </p>
      <label className="file-label">
        选择备份文件
        <input type="file" disabled={busy} onChange={(e) => void pick(e.target.files?.[0])} />
      </label>
      {fileName && <p className="hint">已选择：{fileName}</p>}
      <label>
        备份的主密码
        <input
          type="password"
          value={password}
          onChange={(e) => onPassword(e.target.value)}
          disabled={busy}
          autoComplete="off"
        />
      </label>
      <div className="actions">
        <button
          type="button"
          disabled={busy || bytesB64 === null || password.length === 0}
          onClick={verify}
        >
          {busy ? "验证中…" : "验证备份"}
        </button>
      </div>
    </div>
  );
}

/** 第二步：覆盖确认——展示备份条目数与迁移提示，警示凭据将被整体替换。
 * 确认后（done 阶段）后端已强制锁定会话：锁定屏随状态机接管，本对话框随之卸载。 */
function ConfirmForm({
  bytesB64,
  password,
  busy,
  onClose,
}: {
  bytesB64: string | null;
  password: string;
  busy: boolean;
  onClose: () => void;
}) {
  const importPreview = useSession((s) => s.importPreview)!;
  const importBackup = useSession((s) => s.importBackup);
  const cancelImport = useSession((s) => s.cancelImport);

  const close = () => {
    cancelImport();
    onClose();
  };

  return (
    <div className="confirm-import">
      <p>
        备份验证通过：包含 <strong>{importPreview.entry_count}</strong> 个条目。
      </p>
      {importPreview.schema_migrates && (
        <p className="hint">备份 schema 版本较老，导入后将自动迁移到当前版本。</p>
      )}
      <p className="warn">
        确认后当前保险库的全部条目、主密码与恢复码将被备份中的内容<b>整体替换</b>
        （覆盖前自动存 <code>.bak</code> 可回滚），随后需用备份中的主密码重新解锁。
      </p>
      <div className="actions">
        <button type="button" onClick={close} disabled={busy}>
          取消
        </button>
        <button
          type="button"
          className="danger"
          disabled={busy || bytesB64 === null}
          onClick={() => {
            if (bytesB64 !== null) void importBackup(bytesB64, password, true).catch(() => undefined);
          }}
        >
          {busy ? "导入中…" : "确认覆盖导入"}
        </button>
      </div>
    </div>
  );
}
