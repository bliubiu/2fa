import { describe, expect, it } from "vitest";
import { EntryView } from "./api";
import { diffEntry } from "./diff";

const base: EntryView = {
  id: "0195aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
  id_prefix: "0195aaaa",
  issuer: "GitHub",
  account: "alice",
  code: null,
  remaining_secs: 30,
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  tags: ["工作"],
};

describe("编辑 diff 摘要", () => {
  it("无变化返回空列表", () => {
    expect(diffEntry(base, {})).toEqual([]);
  });

  it("变化的字段逐条列出旧 → 新", () => {
    const lines = diffEntry(base, { issuer: "GitHub2", period: 60, digits: 8 });
    expect(lines).toEqual([
      "服务商：GitHub → GitHub2",
      "位数：6 → 8",
      "周期：30s → 60s",
    ]);
  });

  it("密钥只报已替换，不出现明文", () => {
    const lines = diffEntry(base, { secret: "MZXW6YTBOI" });
    expect(lines).toEqual(["密钥：已替换"]);
    expect(lines[0]).not.toContain("MZXW6YTBOI");
  });

  it("密钥为空串视为不变", () => {
    expect(diffEntry(base, { secret: "" })).toEqual([]);
  });

  it("标签变化列出旧 → 新", () => {
    expect(diffEntry(base, { tags: [] })).toEqual(["标签：工作 → （无）"]);
    expect(diffEntry(base, { tags: ["工作", "新"] })).toEqual(["标签：工作 → 工作、新"]);
  });
});
