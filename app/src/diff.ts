import { EditFields, EntryView } from "./api";

/** 编辑确认用的字段差异摘要（M9-2「保存前展示 diff 摘要」）。
 * 仅列出实际变化的字段；密钥只报「已替换 / 未变」，不出现密钥明文。 */
export function diffEntry(orig: EntryView, form: EditFields): string[] {
  const lines: string[] = [];
  if (form.issuer !== undefined && form.issuer !== orig.issuer)
    lines.push(`服务商：${orig.issuer} → ${form.issuer}`);
  if (form.account !== undefined && form.account !== orig.account)
    lines.push(`账号：${orig.account} → ${form.account}`);
  if (form.algorithm !== undefined && form.algorithm !== orig.algorithm)
    lines.push(`算法：${orig.algorithm} → ${form.algorithm}`);
  if (form.digits !== undefined && form.digits !== orig.digits)
    lines.push(`位数：${orig.digits} → ${form.digits}`);
  if (form.period !== undefined && form.period !== orig.period)
    lines.push(`周期：${orig.period}s → ${form.period}s`);
  if (form.tags !== undefined && form.tags.join("\u0000") !== orig.tags.join("\u0000"))
    lines.push(`标签：${orig.tags.join("、") || "（无）"} → ${form.tags.join("、") || "（无）"}`);
  if (form.secret !== undefined && form.secret !== "") lines.push("密钥：已替换");
  return lines;
}
