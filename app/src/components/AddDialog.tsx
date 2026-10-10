import { FormEvent, useState } from "react";
import { AddDecision, AddSource } from "../api";
import { useSession } from "../store";

/** 添加条目对话框（M9-1）：三来源（otpauth 文本 / 手填 / 图片扫码）两段式——
 * 解析预览 → 同标识冲突逐条决策（覆盖 / 并存）→ 提交落盘。密钥不回传前端。 */
export default function AddDialog({ onClose }: { onClose: () => void }) {
  const pending = useSession((s) => s.pending);
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>添加条目</h1>
          <button type="button" className="ghost" onClick={onClose} disabled={busy}>
            关闭
          </button>
        </header>
        {pending === null ? <SourceForm /> : <PreviewList />}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}

/** 第一步：来源选择与输入。 */
function SourceForm() {
  const previewAdd = useSession((s) => s.previewAdd);
  const busy = useSession((s) => s.busy);
  const [tab, setTab] = useState<"text" | "manual" | "image">("text");

  const tabs: { key: typeof tab; label: string }[] = [
    { key: "text", label: "粘贴 otpauth" },
    { key: "manual", label: "手动填写" },
    { key: "image", label: "图片扫码" },
  ];

  return (
    <div className="add-form">
      <nav className="tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            className={tab === t.key ? "tab active" : "tab"}
            onClick={() => setTab(t.key)}
            disabled={busy}
          >
            {t.label}
          </button>
        ))}
      </nav>
      {tab === "text" && <TextTab disabled={busy} onSubmit={previewAdd} />}
      {tab === "manual" && <ManualTab disabled={busy} onSubmit={previewAdd} />}
      {tab === "image" && <ImageTab disabled={busy} onSubmit={previewAdd} />}
    </div>
  );
}

/** 文本来源：一行一条 otpauth://，或 GA 迁移 URI。 */
function TextTab({
  disabled,
  onSubmit,
}: {
  disabled: boolean;
  onSubmit: (source: AddSource) => void;
}) {
  const [text, setText] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!text.trim()) return;
    onSubmit({ kind: "text", text });
  };
  return (
    <form onSubmit={submit}>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={6}
        placeholder={"otpauth://totp/GitHub:alice?secret=…&issuer=GitHub\notpauth-migration://offline?data=…"}
        aria-label="otpauth 文本"
      />
      <button type="submit" disabled={disabled || !text.trim()}>
        解析预览
      </button>
    </form>
  );
}

/** 手填来源：字段与 CLI add 一致（缺省 SHA1 / 6 位 / 30 秒）。 */
function ManualTab({
  disabled,
  onSubmit,
}: {
  disabled: boolean;
  onSubmit: (source: AddSource) => void;
}) {
  const [issuer, setIssuer] = useState("");
  const [account, setAccount] = useState("");
  const [secret, setSecret] = useState("");
  const [algorithm, setAlgorithm] = useState("SHA1");
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [tags, setTags] = useState("");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!issuer.trim() || !account.trim() || !secret.trim()) return;
    onSubmit({
      kind: "manual",
      issuer,
      account,
      secret,
      algorithm,
      digits,
      period,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t !== ""),
    });
    // 密钥明文即刻清空组件内状态（无论成败）
    setSecret("");
  };

  return (
    <form onSubmit={submit} className="manual-form">
      <label>
        服务商
        <input value={issuer} onChange={(e) => setIssuer(e.target.value)} required />
      </label>
      <label>
        账号
        <input value={account} onChange={(e) => setAccount(e.target.value)} required />
      </label>
      <label>
        密钥（Base32）
        <input
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          required
          autoComplete="off"
        />
      </label>
      <div className="row">
        <label>
          算法
          <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
            <option value="SHA1">SHA1</option>
            <option value="SHA256">SHA256</option>
            <option value="SHA512">SHA512</option>
          </select>
        </label>
        <label>
          位数
          <select value={digits} onChange={(e) => setDigits(Number(e.target.value))}>
            <option value={6}>6</option>
            <option value={8}>8</option>
          </select>
        </label>
        <label>
          周期（秒）
          <input
            type="number"
            min={1}
            value={period}
            onChange={(e) => setPeriod(Number(e.target.value))}
          />
        </label>
      </div>
      <label>
        标签（逗号分隔，可空）
        <input value={tags} onChange={(e) => setTags(e.target.value)} />
      </label>
      <button type="submit" disabled={disabled}>
        解析预览
      </button>
    </form>
  );
}

/** 图片来源：选择含二维码的图片文件（读取字节 Base64 传后端解码）。 */
function ImageTab({
  disabled,
  onSubmit,
}: {
  disabled: boolean;
  onSubmit: (source: AddSource) => void;
}) {
  const [fileName, setFileName] = useState<string | null>(null);

  const pick = async (file: File | undefined) => {
    if (!file) return;
    setFileName(file.name);
    // readAsDataURL → data:image/…;base64,xxxx → 截取 Base64 段
    const dataUrl = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(new Error("读取文件失败"));
      reader.readAsDataURL(file);
    });
    const base64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
    onSubmit({ kind: "image", bytes_b64: base64 });
  };

  return (
    <div className="image-form">
      <label className="file-label">
        选择图片文件
        <input
          type="file"
          accept="image/*"
          disabled={disabled}
          onChange={(e) => void pick(e.target.files?.[0])}
        />
      </label>
      {fileName && <p className="hint">已选择：{fileName}</p>}
      <p className="hint">支持 otpauth 与 Google Authenticator 迁移二维码；多批次请逐张导入。</p>
    </div>
  );
}

/** 第二步：预览列表与冲突决策。 */
function PreviewList() {
  const pending = useSession((s) => s.pending)!;
  const busy = useSession((s) => s.busy);
  const commitAdd = useSession((s) => s.commitAdd);
  const cancelAdd = useSession((s) => s.cancelAdd);
  // 冲突决策：index → action；未选的冲突条目在提交时报错（后端同样把关）
  const [decisions, setDecisions] = useState<Map<number, AddDecision["action"]>>(new Map());
  const undecided = pending.items.filter((i) => i.conflict && !decisions.has(i.index));

  const submit = () => {
    commitAdd([...decisions.entries()].map(([index, action]) => ({ index, action })));
  };

  return (
    <div className="preview">
      <p className="hint">确认以下条目后写入保险库：</p>
      <table>
        <thead>
          <tr>
            <th>服务商 / 账号</th>
            <th>参数</th>
            <th>冲突处理</th>
          </tr>
        </thead>
        <tbody>
          {pending.items.map((item) => (
            <tr key={item.index}>
              <td>
                {item.issuer}
                <div className="account">{item.account}</div>
              </td>
              <td>
                {item.algorithm} / {item.digits} 位 / {item.period}s
                {item.tags.length > 0 && (
                  <div className="account">标签：{item.tags.join("、")}</div>
                )}
              </td>
              <td>
                {item.duplicate && <span className="badge">与既有条目重复，将跳过</span>}
                {item.conflict && (
                  <ConflictChoice
                    value={decisions.get(item.index) ?? null}
                    onChange={(action) => {
                      setDecisions((prev) => {
                        const next = new Map(prev);
                        if (action === null) {
                          next.delete(item.index);
                        } else {
                          next.set(item.index, action);
                        }
                        return next;
                      });
                    }}
                  />
                )}
                {!item.conflict && !item.duplicate && <span className="badge ok">新增</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {pending.failed.length > 0 && (
        <div className="failed">
          {pending.failed.map((f) => (
            <p key={f.line} className="error">
              第 {f.line} 行解析失败：{f.error}
            </p>
          ))}
        </div>
      )}
      {pending.notes.map((note, i) => (
        <p key={i} className="hint">
          {note}
        </p>
      ))}
      {pending.migration_used && (
        <p className="warn">
          安全提醒：迁移载荷中的密钥为明文形式，请立即删除 Google Authenticator
          中的原始迁移二维码（截图/图片）。
        </p>
      )}
      <div className="actions">
        <button type="button" onClick={cancelAdd} disabled={busy}>
          取消
        </button>
        <button
          type="button"
          onClick={submit}
          disabled={busy || undecided.length > 0}
          title={undecided.length > 0 ? "存在未决策的冲突条目" : undefined}
        >
          {busy ? "写入中…" : "确认写入"}
        </button>
      </div>
    </div>
  );
}

/** 冲突行决策控件：覆盖 / 并存（取消 = 移除决策，提交按钮将禁用）。 */
function ConflictChoice({
  value,
  onChange,
}: {
  value: AddDecision["action"] | null;
  onChange: (action: AddDecision["action"] | null) => void;
}) {
  return (
    <div className="conflict">
      <span className="badge warn-badge">同标识密钥不同</span>
      <label>
        <input
          type="radio"
          checked={value === "overwrite"}
          onChange={() => onChange("overwrite")}
        />
        覆盖
      </label>
      <label>
        <input type="radio" checked={value === "keep_both"} onChange={() => onChange("keep_both")} />
        并存
      </label>
      {value !== null && (
        <button type="button" className="ghost" onClick={() => onChange(null)}>
          重选
        </button>
      )}
    </div>
  );
}
