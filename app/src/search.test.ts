import { describe, expect, it } from "vitest";
import { EntryView } from "./api";
import { findMatches } from "./search";

function entry(overrides: Partial<EntryView>): EntryView {
  return {
    id: "0195aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    id_prefix: "0195aaaa",
    issuer: "GitHub",
    account: "alice@example.com",
    code: null,
    remaining_secs: 30,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    tags: [],
    ...overrides,
  };
}

const fixture: EntryView[] = [
  entry({ issuer: "GitHub", account: "alice", tags: ["工作"] }),
  entry({ issuer: "GitLab", account: "bob", tags: ["个人", "运维"] }),
  entry({ issuer: "Steam", account: "carol", tags: [] }),
];

describe("搜索过滤（与 CLI find 同语义）", () => {
  it("空查询返回全部", () => {
    expect(findMatches(fixture, "")).toHaveLength(3);
    expect(findMatches(fixture, "   ")).toHaveLength(3);
  });

  it("服务商大小写不敏感子串匹配", () => {
    expect(findMatches(fixture, "git")).toHaveLength(2);
    expect(findMatches(fixture, "GITHUB")).toHaveLength(1);
  });

  it("账号匹配", () => {
    expect(findMatches(fixture, "alice")).toHaveLength(1);
    expect(findMatches(fixture, "CAROL")).toHaveLength(1);
  });

  it("标签匹配", () => {
    expect(findMatches(fixture, "运维")).toHaveLength(1);
    expect(findMatches(fixture, "个人")).toHaveLength(1);
  });

  it("无匹配返回空列表", () => {
    expect(findMatches(fixture, "不存在")).toHaveLength(0);
  });
});
