import { FormEvent, useState } from "react";
import { EditFields, EntryView } from "../api";
import { diffEntry } from "../diff";
import { useSession } from "../store";

/** 编辑条目对话框（M9-2）：字段级修改，保存前展示 diff 摘要；
 * 密钥留空表示不变，填写则整体替换。语义对齐 CLI `edit`。 */
export default function EditDialog({ entry, onClose }: { entry: EntryView; onClose: () => void }) {
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const editEntry = useSession((s) => s.editEntry);
  const [form, setForm] = useState<Required<Omit<EditFields, "secret">> & { secret: string }>({
    issuer: entry.issuer,
    account: entry.account,
    secret: "",
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    tags: entry.tags,
  });
  const [confirming, setConfirming] = useState(false);

  // 提交前组装字段：密钥留空 → 不传（不变）
  const fields: EditFields = {
    issuer: form.issuer,
    account: form.account,
    secret: form.secret === "" ? undefined : form.secret,
    algorithm: form.algorithm,
    digits: form.digits,
    period: form.period,
    tags: form.tags,
  };
  const diff = diffEntry(entry, fields);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setConfirming(true);
  };

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>
            编辑条目 <span className="account">{entry.issuer} / {entry.account}</span>
          </h1>
          <button type="button" className="ghost" onClick={onClose} disabled={busy}>
            关闭
          </button>
        </header>
        {confirming ? (
          <div className="preview">
            <p className="hint">即将保存以下修改：</p>
            {diff.length === 0 ? (
              <p className="hint">没有字段变化。</p>
            ) : (
              <ul className="diff-list">
                {diff.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            )}
            <div className="actions">
              <button type="button" onClick={() => setConfirming(false)} disabled={busy}>
                返回修改
              </button>
              <button
                type="button"
                disabled={busy || diff.length === 0}
                onClick={() => void editEntry(entry.id_prefix, fields)}
              >
                {busy ? "保存中…" : "确认保存"}
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} className="manual-form">
            <label>
              服务商
              <input
                value={form.issuer}
                onChange={(e) => setForm({ ...form, issuer: e.target.value })}
                required
              />
            </label>
            <label>
              账号
              <input
                value={form.account}
                onChange={(e) => setForm({ ...form, account: e.target.value })}
                required
              />
            </label>
            <label>
              密钥（Base32，留空表示不变）
              <input
                type="password"
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
                autoComplete="off"
                placeholder="留空保持原密钥"
              />
            </label>
            <div className="row">
              <label>
                算法
                <select
                  value={form.algorithm}
                  onChange={(e) => setForm({ ...form, algorithm: e.target.value })}
                >
                  <option value="SHA1">SHA1</option>
                  <option value="SHA256">SHA256</option>
                  <option value="SHA512">SHA512</option>
                </select>
              </label>
              <label>
                位数
                <select
                  value={form.digits}
                  onChange={(e) => setForm({ ...form, digits: Number(e.target.value) })}
                >
                  <option value={6}>6</option>
                  <option value={8}>8</option>
                </select>
              </label>
              <label>
                周期（秒）
                <input
                  type="number"
                  min={1}
                  value={form.period}
                  onChange={(e) => setForm({ ...form, period: Number(e.target.value) })}
                />
              </label>
            </div>
            <label>
              标签（逗号分隔，可空）
              <input
                value={form.tags.join(",")}
                onChange={(e) =>
                  setForm({
                    ...form,
                    tags: e.target.value
                      .split(",")
                      .map((t) => t.trim())
                      .filter((t) => t !== ""),
                  })
                }
              />
            </label>
            <button type="submit" disabled={busy}>
              检查修改
            </button>
          </form>
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
