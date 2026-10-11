import { EntryView } from "./api";

/** 搜索过滤（与 CLI `find` 同语义）：查询词小写化后对 issuer / account /
 * 任一标签做子串匹配；空查询返回全部。 */
export function findMatches(entries: EntryView[], query: string): EntryView[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") return entries;
  return entries.filter(
    (e) =>
      e.issuer.toLowerCase().includes(needle) ||
      e.account.toLowerCase().includes(needle) ||
      e.tags.some((t) => t.toLowerCase().includes(needle)),
  );
}
