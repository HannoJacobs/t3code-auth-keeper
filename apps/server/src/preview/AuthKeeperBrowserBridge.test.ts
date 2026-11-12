// @effect-diagnostics nodeBuiltinImport:off - Tests private native integration files.
import * as NodeFSP from "node:fs/promises";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import { afterEach, expect, it } from "vite-plus/test";

import { startAuthKeeperBrowserBridge } from "./AuthKeeperBrowserBridge.ts";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) => NodeFSP.rm(directory, { recursive: true })),
  );
});

async function fixture(source: string) {
  const directory = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-owner-browser-"));
  directories.push(directory);
  const module = NodePath.join(directory, "bridge.cjs");
  const manifest = NodePath.join(directory, "manifest.json");
  await NodeFSP.writeFile(module, source, { mode: 0o600 });
  const value = {
    protocol: 1,
    module,
    sha256: NodeCrypto.createHash("sha256").update(source).digest("hex"),
  };
  await NodeFSP.writeFile(manifest, JSON.stringify(value), { mode: 0o600 });
  return { directory, module, manifest, value };
}

const callbacks = {
  runtime: { kind: "server" as const, pid: process.pid, stateDir: "/owner/state" },
  withPage: async () => {
    throw new Error("page not requested");
  },
  handoff: async () => {
    throw new Error("handoff not requested");
  },
};

it("does nothing without explicit enrollment and rejects an unpinned or unsafe module before loading it", async () => {
  expect(await startAuthKeeperBrowserBridge(undefined, callbacks)).toBeUndefined();
  const f = await fixture('throw new Error("module executed");');
  await NodeFSP.writeFile(f.module, 'throw new Error("changed module executed");');
  await expect(startAuthKeeperBrowserBridge(f.manifest, callbacks)).rejects.toThrow(
    "auth_keeper_bridge_pin_invalid",
  );
  await NodeFSP.writeFile(f.module, 'throw new Error("module executed");');
  await NodeFSP.chmod(f.manifest, 0o644);
  await expect(startAuthKeeperBrowserBridge(f.manifest, callbacks)).rejects.toThrow(
    "auth_keeper_bridge_manifest_unsafe",
  );
  await NodeFSP.chmod(f.manifest, 0o600);
  await NodeFSP.unlink(f.module);
  await NodeFSP.symlink(NodePath.join(f.directory, "elsewhere"), f.module);
  await expect(startAuthKeeperBrowserBridge(f.manifest, callbacks)).rejects.toThrow(
    "auth_keeper_bridge_module_unsafe",
  );
});

it("loads only the pinned ABI and returns its scoped lifecycle and enrolled profile catalogue", async () => {
  const f = await fixture(`module.exports = {
    protocol: 1,
    start: async ({runtime}) => ({
      profiles: [{id: "auth-keeper-personal", name: "Personal Google", kind: "persistent"}],
      close: async () => { require("node:fs").writeFileSync(${JSON.stringify("PLACEHOLDER")}, "closed"); },
      runtime
    })
  };`);
  const source = (await NodeFSP.readFile(f.module, "utf8")).replace(
    "PLACEHOLDER",
    NodePath.join(f.directory, "closed"),
  );
  await NodeFSP.writeFile(f.module, source);
  await NodeFSP.writeFile(
    f.manifest,
    JSON.stringify({
      ...f.value,
      sha256: NodeCrypto.createHash("sha256").update(source).digest("hex"),
    }),
  );
  const bridge = await startAuthKeeperBrowserBridge(f.manifest, callbacks);
  expect(bridge?.profiles).toEqual([
    { id: "auth-keeper-personal", name: "Personal Google", kind: "persistent" },
  ]);
  await bridge?.close();
  expect(await NodeFSP.readFile(NodePath.join(f.directory, "closed"), "utf8")).toBe("closed");
});

it("rejects a different protocol without starting the module", async () => {
  const f = await fixture(
    'module.exports = {protocol: 2, start: () => { throw new Error("started"); }};',
  );
  await expect(startAuthKeeperBrowserBridge(f.manifest, callbacks)).rejects.toThrow(
    "auth_keeper_bridge_protocol_invalid",
  );
});

it("does not let an installed bridge borrow Default or incognito contexts", async () => {
  const f = await fixture(`module.exports = {protocol:1, start:async ({withPage}) => {
    await withPage("default", async () => undefined);
    return {profiles:[],close:async()=>{}};
  }};`);
  await expect(startAuthKeeperBrowserBridge(f.manifest, callbacks)).rejects.toThrow(
    "auth_keeper_bridge_profile_invalid",
  );
});
