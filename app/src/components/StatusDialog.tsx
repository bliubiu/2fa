import { useEffect, useState } from "react";
import { api } from "../api";
import { useSession } from "../store";

/** 状态页（M9-4）：路径、来源、条目数、KDF 版本（与 CLI `status` 同字段，
 * 数据来自既有 `status` 命令的 `StatusView`）。 */
export default function StatusDialog({ onClose }: { onClose: () => void }) {
  const [view, setView] = useState<Awaited<ReturnType<typeof api.status>> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const error = useSession((s) => s.error);

  useEffect(() => {
    // 打开时取一次权威状态（条目数与 KDF 版本以后端为准）
    api
      .status()
      .then(setView)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>保险库状态</h1>
          <button type="button" className="ghost" onClick={onClose}>
            关闭
          </button>
        </header>
        {view === null ? (
          <p className="hint">{err ?? "读取中…"}</p>
        ) : (
          <table className="secret-table">
            <tbody>
              <tr>
                <th>保险库路径</th>
                <td className="account">{view.path}</td>
              </tr>
              <tr>
                <th>路径来源</th>
                <td>{view.source}</td>
              </tr>
              <tr>
                <th>条目数</th>
                <td>{view.entry_count ?? "（锁定）"}</td>
              </tr>
              <tr>
                <th>KDF 版本</th>
                <td>{view.kdf_versions ?? "（锁定）"}</td>
              </tr>
            </tbody>
          </table>
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
