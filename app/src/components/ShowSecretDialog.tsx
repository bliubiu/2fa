import { useSession } from "../store";

/** 查看密钥（`show` 等价，M9-3）：确认弹窗提示明文风险（截图、录屏、旁观都会
 * 泄露）→ 用户确认后才向后端取回明细与明文密钥；关闭即清出前端状态。 */
export default function ShowSecretDialog({ prefix, onClose }: { prefix: string; onClose: () => void }) {
  const busy = useSession((s) => s.busy);
  const error = useSession((s) => s.error);
  const secretView = useSession((s) => s.secretView);
  const showSecret = useSession((s) => s.showSecret);
  const clearSecretView = useSession((s) => s.clearSecretView);

  const close = () => {
    // 密钥即刻离开前端状态，再卸载
    clearSecretView();
    onClose();
  };

  // 明细未取回：确认态（点击「确认显示」才向后端取回密钥）
  if (secretView === null) {
    return (
      <div className="modal-mask">
        <div className="modal">
          <h1>显示明文密钥？</h1>
          <p className="warn">即将显示明文密钥（截图、录屏、旁观都会泄露），确认显示？</p>
          <div className="actions">
            <button type="button" onClick={close}>
              取消
            </button>
            <button
              type="button"
              className="danger"
              disabled={busy}
              onClick={() => void showSecret(prefix).catch(() => undefined)}
            >
              {busy ? "取回中…" : "确认显示"}
            </button>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
      </div>
    );
  }

  // 明细态：字段与明文密钥展示
  const view = secretView;
  return (
    <div className="modal-mask">
      <div className="modal">
        <header>
          <h1>条目详情（含明文密钥）</h1>
          <button type="button" className="ghost" onClick={close} disabled={busy}>
            关闭
          </button>
        </header>
        <table className="secret-table">
          <tbody>
            <tr>
              <th>服务商</th>
              <td>{view.issuer}</td>
            </tr>
            <tr>
              <th>账号</th>
              <td>{view.account}</td>
            </tr>
            <tr>
              <th>算法 / 位数 / 周期</th>
              <td>
                {view.algorithm} / {view.digits} 位 / {view.period}s
              </td>
            </tr>
            <tr>
              <th>标签</th>
              <td>{view.tags.length === 0 ? "（无）" : view.tags.join("、")}</td>
            </tr>
            <tr>
              <th>当前验证码</th>
              <td>
                {view.code === null ? (
                  <span className="code code-error">错误</span>
                ) : (
                  `${view.code}（剩余 ${view.remaining_secs}s）`
                )}
              </td>
            </tr>
            <tr>
              <th>密钥（明文）</th>
              <td>
                <code className="secret-text">{view.secret}</code>
              </td>
            </tr>
            <tr>
              <th>ID</th>
              <td className="account">{view.id}</td>
            </tr>
          </tbody>
        </table>
        <p className="warn">该密钥为明文：请勿截图传播，用完立即关闭本窗口。</p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
