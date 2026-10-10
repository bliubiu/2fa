import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: {
      unlock: vi.fn(),
      lock: vi.fn(),
      status: vi.fn(),
      listEntries: vi.fn(),
      checkIdle: vi.fn(),
      copyCode: vi.fn(),
    },
  };
});

import { api } from "./api";
import { useSession } from "./store";

const mocked = vi.mocked(api);

/** 两条不同周期的条目（边界条目 remaining=1，普通条目 remaining=45）。 */
function entries_fixture() {
  return [
    {
      id: "0195aaaa-0000-7000-8000-000000000001",
      id_prefix: "0195aaaa",
      issuer: "GitHub",
      account: "alice",
      code: "123456",
      remaining_secs: 1,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      tags: [],
    },
    {
      id: "0195aaaa-0000-7000-8000-000000000002",
      id_prefix: "0195aaaa",
      issuer: "Example",
      account: "bob",
      code: "654321",
      remaining_secs: 45,
      algorithm: "SHA256",
      digits: 8,
      period: 60,
      tags: ["工作"],
    },
  ];
}

beforeEach(() => {
  vi.clearAllMocks();
  useSession.setState({
    status: "locked",
    entries: [],
    error: null,
    notice: null,
    busy: false,
  });
});

describe("会话状态机", () => {
  it("解锁成功进入 unlocked 并加载列表与路径", async () => {
    mocked.unlock.mockResolvedValue({ entry_count: 2 });
    mocked.status.mockResolvedValue({
      path: "C:/v/vault.json",
      source: "平台惯例",
      unlocked: true,
      entry_count: 2,
      kdf_versions: "v1",
    });
    mocked.listEntries.mockResolvedValue(entries_fixture());

    await useSession.getState().unlock("主密码");

    expect(useSession.getState().status).toBe("unlocked");
    expect(useSession.getState().entries).toHaveLength(2);
    expect(useSession.getState().vaultPath).toBe("C:/v/vault.json");
    expect(useSession.getState().error).toBeNull();
  });

  it("解锁失败展示中文错误并停留在解锁屏", async () => {
    mocked.unlock.mockRejectedValue({ kind: "auth", message: "认证失败：主密码错误" });

    await useSession.getState().unlock("错误密码");

    expect(useSession.getState().status).toBe("locked");
    expect(useSession.getState().error).toBe("认证失败：主密码错误");
    expect(useSession.getState().entries).toHaveLength(0);
  });

  it("锁定回到解锁屏并清空条目（后端密钥归零）", async () => {
    mocked.lock.mockResolvedValue(true);
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    await useSession.getState().lock();

    expect(useSession.getState().status).toBe("locked");
    expect(useSession.getState().entries).toHaveLength(0);
  });
});

describe("每秒 tick", () => {
  it("非边界秒本地递减，不请求后端", () => {
    useSession.setState({ status: "unlocked", entries: [entries_fixture()[1]] });

    useSession.getState().tick();

    expect(useSession.getState().entries[0].remaining_secs).toBe(44);
    expect(mocked.listEntries).not.toHaveBeenCalled();
  });

  it("任一条目到周期边界即回后端刷新，本地值保持等权威值覆盖", async () => {
    mocked.listEntries.mockResolvedValue([
      { ...entries_fixture()[0], remaining_secs: 30, code: "999999" },
      ...entries_fixture().slice(1),
    ]);
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    useSession.getState().tick();

    // 边界 tick：立即请求后端；本地值在刷新落地前不变
    expect(mocked.listEntries).toHaveBeenCalledTimes(1);
    expect(useSession.getState().entries[0].remaining_secs).toBe(1);

    // 刷新完成后验证码与剩余秒来自后端权威值（验证码切换）
    await vi.waitFor(() => {
      const refreshed = useSession.getState().entries;
      expect(refreshed[0].code).toBe("999999");
      expect(refreshed[0].remaining_secs).toBe(30);
    });
  });

  it("锁定状态下 tick 不做任何事", () => {
    useSession.setState({ status: "locked", entries: [] });
    useSession.getState().tick();
    expect(mocked.listEntries).not.toHaveBeenCalled();
  });

  it("刷新失败（如后端已锁定）回到解锁屏并展示错误", async () => {
    mocked.listEntries.mockRejectedValue({ kind: "locked", message: "保险库处于锁定状态，请先解锁" });
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    useSession.getState().tick();

    await vi.waitFor(() => expect(useSession.getState().status).toBe("locked"));
    expect(useSession.getState().entries).toHaveLength(0);
  });
});

describe("空闲超时心跳", () => {
  it("后端判定空闲超时回锁屏并提示密钥已归零", async () => {
    mocked.checkIdle.mockResolvedValue(true);
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    await useSession.getState().checkIdle();

    expect(useSession.getState().status).toBe("locked");
    expect(useSession.getState().entries).toHaveLength(0);
    expect(useSession.getState().error).toBe("空闲超时，已自动锁定（密钥已归零）");
  });

  it("未超时保持解锁且不清空条目", async () => {
    mocked.checkIdle.mockResolvedValue(false);
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    await useSession.getState().checkIdle();

    expect(useSession.getState().status).toBe("unlocked");
    expect(useSession.getState().entries).toHaveLength(2);
    expect(useSession.getState().error).toBeNull();
  });

  it("心跳失败（会话已被后端锁定）回解锁屏", async () => {
    mocked.checkIdle.mockRejectedValue({ kind: "locked", message: "保险库处于锁定状态，请先解锁" });
    useSession.setState({ status: "unlocked", entries: entries_fixture() });

    await useSession.getState().checkIdle();

    expect(useSession.getState().status).toBe("locked");
    expect(useSession.getState().entries).toHaveLength(0);
  });
});

describe("复制验证码", () => {
  it("复制成功展示自动清除提示", async () => {
    mocked.copyCode.mockResolvedValue(undefined);

    await useSession.getState().copyCode("0195aaaa");

    expect(useSession.getState().notice).toBe("已复制，30 秒后自动清除剪贴板");
    expect(useSession.getState().error).toBeNull();
  });

  it("复制失败展示中文错误", async () => {
    mocked.copyCode.mockRejectedValue({ kind: "not_found", message: "未找到条目：0195aaaa" });

    await useSession.getState().copyCode("0195aaaa");

    expect(useSession.getState().error).toBe("未找到条目：0195aaaa");
    expect(useSession.getState().notice).toBeNull();
  });
});
