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
      addPreview: vi.fn(),
      addCommit: vi.fn(),
      editEntry: vi.fn(),
      deleteEntry: vi.fn(),
      exportBackup: vi.fn(),
      importBackup: vi.fn(),
      exportPlain: vi.fn(),
      showEntry: vi.fn(),
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
    pending: null,
    importPreview: null,
    secretView: null,
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

describe("添加条目（两段式）", () => {
  it("预览成功暂存 pending 并清错误", async () => {
    const preview = {
      token: 7,
      items: [
        { index: 0, issuer: "GitHub", account: "alice", algorithm: "SHA1", digits: 6, period: 30, tags: [], conflict: false, duplicate: false },
      ],
      failed: [],
      notes: [],
      migration_used: false,
    };
    mocked.addPreview.mockResolvedValue(preview);
    useSession.setState({ status: "unlocked", error: "旧错误" });

    await useSession.getState().previewAdd({ kind: "text", text: "otpauth://totp/x" });

    expect(useSession.getState().pending).toEqual(preview);
    expect(useSession.getState().error).toBeNull();
    expect(useSession.getState().busy).toBe(false);
  });

  it("预览失败清 pending 并展示中文错误", async () => {
    mocked.addPreview.mockRejectedValue({ kind: "other", message: "二维码解码失败：非二维码图片" });

    await useSession.getState().previewAdd({ kind: "image", bytes_b64: "aGk=" });

    expect(useSession.getState().pending).toBeNull();
    expect(useSession.getState().error).toBe("二维码解码失败：非二维码图片");
  });

  it("提交成功清 pending、发提示并刷新列表", async () => {
    const preview = {
      token: 9,
      items: [],
      failed: [],
      notes: [],
      migration_used: false,
    };
    mocked.addPreview.mockResolvedValue(preview);
    mocked.addCommit.mockResolvedValue({ added: 2, replaced: 1, kept_both: 0, skipped_dup: 1, changed: true });
    mocked.listEntries.mockResolvedValue(entries_fixture());
    useSession.setState({ status: "unlocked" });
    await useSession.getState().previewAdd({ kind: "text", text: "otpauth://totp/x" });

    await useSession.getState().commitAdd([{ index: 0, action: "overwrite" }]);

    expect(mocked.addCommit).toHaveBeenCalledWith(9, [{ index: 0, action: "overwrite" }]);
    expect(useSession.getState().pending).toBeNull();
    expect(useSession.getState().notice).toBe("添加完成：新增 2，覆盖 1，跳过重复 1");
    expect(useSession.getState().entries).toHaveLength(2);
  });

  it("提交失败保留 pending 并展示中文错误", async () => {
    const preview = { token: 3, items: [], failed: [], notes: [], migration_used: false };
    mocked.addPreview.mockResolvedValue(preview);
    mocked.addCommit.mockRejectedValue({
      kind: "other",
      message: "条目 1（GitHub / alice）与既有条目同标识但密钥不同，请先选择覆盖或并存",
    });
    useSession.setState({ status: "unlocked" });
    await useSession.getState().previewAdd({ kind: "text", text: "otpauth://totp/x" });

    await useSession.getState().commitAdd([]);

    expect(useSession.getState().pending).toEqual(preview);
    expect(useSession.getState().error).toContain("覆盖或并存");
  });

  it("取消清 pending", () => {
    useSession.setState({
      pending: { token: 1, items: [], failed: [], notes: [], migration_used: false },
    });

    useSession.getState().cancelAdd();

    expect(useSession.getState().pending).toBeNull();
  });
});

describe("编辑与删除条目", () => {
  it("编辑成功发提示并刷新列表", async () => {
    mocked.editEntry.mockResolvedValue(undefined);
    mocked.listEntries.mockResolvedValue(entries_fixture());
    useSession.setState({ status: "unlocked" });

    await useSession.getState().editEntry("0195aaaa", { issuer: "GitHub2" });

    expect(mocked.editEntry).toHaveBeenCalledWith("0195aaaa", { issuer: "GitHub2" });
    expect(useSession.getState().notice).toBe("已保存修改");
    expect(useSession.getState().entries).toHaveLength(2);
  });

  it("编辑失败展示中文错误", async () => {
    mocked.editEntry.mockRejectedValue({ kind: "other", message: "修改后字段非法：位数为 6 / 8 之外的值：7" });

    await useSession.getState().editEntry("0195aaaa", { digits: 7 });

    expect(useSession.getState().error).toContain("修改后字段非法");
    expect(useSession.getState().notice).toBeNull();
  });

  it("删除成功发含条目描述的提示并刷新列表", async () => {
    mocked.deleteEntry.mockResolvedValue("GitHub / alice");
    mocked.listEntries.mockResolvedValue(entries_fixture());
    useSession.setState({ status: "unlocked" });

    await useSession.getState().deleteEntry("0195aaaa");

    expect(mocked.deleteEntry).toHaveBeenCalledWith("0195aaaa");
    expect(useSession.getState().notice).toBe("已删除条目：GitHub / alice");
    expect(useSession.getState().entries).toHaveLength(2);
  });

  it("删除失败展示中文错误", async () => {
    mocked.deleteEntry.mockRejectedValue({ kind: "not_found", message: "未找到条目：ffffffff" });

    await useSession.getState().deleteEntry("ffffffff");

    expect(useSession.getState().error).toBe("未找到条目：ffffffff");
  });
});

describe("导入导出（M9-3）", () => {
  it("导出备份成功回显路径与字节数", async () => {
    mocked.exportBackup.mockResolvedValue({ path: "D:/backup/vault.json", bytes: 930 });

    await useSession.getState().exportBackup("D:/backup/vault.json");

    expect(mocked.exportBackup).toHaveBeenCalledWith("D:/backup/vault.json");
    expect(useSession.getState().notice).toBe("加密备份已导出：D:/backup/vault.json（930 字节，字节级拷贝）");
    expect(useSession.getState().error).toBeNull();
  });

  it("导出备份失败展示中文错误", async () => {
    mocked.exportBackup.mockRejectedValue({ kind: "other", message: "导出路径与保险库相同，会覆盖保险库本体，请另选路径" });

    await useSession.getState().exportBackup("C:/v/vault.json");

    expect(useSession.getState().error).toContain("保险库相同");
  });

  it("导入备份第一段进入确认态并回显条目数与迁移标记", async () => {
    mocked.importBackup.mockResolvedValue({ stage: "need_confirm", entry_count: 5, schema_migrates: true });

    const out = await useSession.getState().importBackup("aGk=", "备份主密码", false);

    expect(mocked.importBackup).toHaveBeenCalledWith("aGk=", "备份主密码", false);
    expect(out.stage).toBe("need_confirm");
    expect(useSession.getState().importPreview).toEqual({ entry_count: 5, schema_migrates: true });
  });

  it("导入备份确认后回解锁屏并提示用备份主密码重新解锁", async () => {
    mocked.importBackup.mockResolvedValue({ stage: "done", entry_count: 5 });
    useSession.setState({ status: "unlocked", entries: entries_fixture(), importPreview: { entry_count: 5, schema_migrates: false } });

    const out = await useSession.getState().importBackup("aGk=", "备份主密码", true);

    expect(mocked.importBackup).toHaveBeenCalledWith("aGk=", "备份主密码", true);
    expect(out.stage).toBe("done");
    expect(useSession.getState().status).toBe("locked");
    expect(useSession.getState().entries).toHaveLength(0);
    expect(useSession.getState().importPreview).toBeNull();
    expect(useSession.getState().notice).toBe("已导入 5 个条目，请用备份中的主密码重新解锁");
  });

  it("导入备份密码错误展示明确指向备份主密码的错误", async () => {
    mocked.importBackup.mockRejectedValue({ kind: "other", message: "认证失败：备份文件的主密码错误" });

    await useSession.getState().importBackup("aGk=", "错误密码", false).catch(() => undefined);

    expect(useSession.getState().error).toBe("认证失败：备份文件的主密码错误");
    expect(useSession.getState().importPreview).toBeNull();
  });

  it("取消导入清确认态", () => {
    useSession.setState({ importPreview: { entry_count: 3, schema_migrates: false } });

    useSession.getState().cancelImport();

    expect(useSession.getState().importPreview).toBeNull();
  });

  it("明文导出成功返回结果供对话框展示删除强提示", async () => {
    mocked.exportPlain.mockResolvedValue({ path: "D:/out/plain.txt", bytes: 420 });

    const out = await useSession.getState().exportPlain("D:/out/plain.txt", "2");

    expect(mocked.exportPlain).toHaveBeenCalledWith("D:/out/plain.txt", "2");
    expect(out).toEqual({ path: "D:/out/plain.txt", bytes: 420 });
  });

  it("明文导出确认数不符展示后端中文错误", async () => {
    mocked.exportPlain.mockRejectedValue({ kind: "other", message: "确认失败：输入的条目数与当前条目数（2）不一致，已取消导出" });

    await useSession.getState().exportPlain("D:/out/plain.txt", "3").catch(() => undefined);

    expect(useSession.getState().error).toContain("不一致");
  });
});

describe("查看密钥（show 等价）", () => {
  it("确认后展示密钥视图并关闭时即刻清空", async () => {
    const view = { ...entries_fixture()[0], secret: "JBSWY3DPEHPK3PXP" };
    mocked.showEntry.mockResolvedValue(view);

    await useSession.getState().showSecret("0195aaaa");

    expect(mocked.showEntry).toHaveBeenCalledWith("0195aaaa");
    expect(useSession.getState().secretView).toEqual(view);

    useSession.getState().clearSecretView();
    expect(useSession.getState().secretView).toBeNull();
  });

  it("查看失败展示中文错误", async () => {
    mocked.showEntry.mockRejectedValue({ kind: "not_found", message: "未找到条目：ffffffff" });

    await useSession.getState().showSecret("ffffffff");

    expect(useSession.getState().error).toBe("未找到条目：ffffffff");
    expect(useSession.getState().secretView).toBeNull();
  });

  it("锁定时密钥视图同步清空（密钥不留存前端状态）", async () => {
    mocked.lock.mockResolvedValue(true);
    useSession.setState({
      status: "unlocked",
      entries: entries_fixture(),
      secretView: { ...entries_fixture()[0], secret: "JBSWY3DPEHPK3PXP" },
    });

    await useSession.getState().lock();

    expect(useSession.getState().secretView).toBeNull();
  });
});
