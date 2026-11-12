// @effect-diagnostics nodeBuiltinImport:off - Private owner integration shares Playwright's native lifecycle.
import { type BrowserProfile, BrowserProfile as BrowserProfileSchema } from "@t3tools/contracts";
import * as Schema from "effect/Schema";
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeModule from "node:module";
import type { Page } from "playwright-core";

export interface AuthKeeperBrowserCallbacks {
  readonly runtime: { readonly kind: "server"; readonly pid: number; readonly stateDir: string };
  readonly withPage: <A>(profileId: string, run: (page: Page) => Promise<A>) => Promise<A>;
  readonly handoff: (input: {
    readonly profileId: string;
    readonly url: string;
    readonly threadId: string;
  }) => Promise<{ readonly tabId: string }>;
  readonly closeHandoff: (profileId: string) => Promise<void>;
}

export interface AuthKeeperBrowserIntegration {
  readonly profiles: ReadonlyArray<BrowserProfile>;
  readonly close: () => Promise<void>;
}

const isBrowserProfile = Schema.is(BrowserProfileSchema);
const managedProfiles = new Set(["auth-keeper-work", "auth-keeper-personal"]);

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object";

async function ownedFile(file: string, privateFile: boolean, code: string) {
  if (!NodePath.isAbsolute(file) || /[\x00-\x1f]/.test(file)) throw new Error(code);
  const info = await NodeFSP.lstat(file);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.uid !== process.getuid?.() ||
    (info.mode & (privateFile ? 0o077 : 0o022)) !== 0
  )
    throw new Error(code);
  const parent = await NodeFSP.stat(NodePath.dirname(file));
  if (parent.uid !== process.getuid?.() || (parent.mode & 0o022) !== 0) throw new Error(code);
  return NodeFSP.readFile(file);
}

export async function startAuthKeeperBrowserBridge(
  manifestPath: string | undefined,
  callbacks: AuthKeeperBrowserCallbacks,
): Promise<AuthKeeperBrowserIntegration | undefined> {
  if (manifestPath === undefined) return undefined;
  const bytes = await ownedFile(manifestPath, true, "auth_keeper_bridge_manifest_unsafe");
  if (bytes.length > 8192) throw new Error("auth_keeper_bridge_manifest_invalid");
  const manifest: unknown = JSON.parse(bytes.toString("utf8"));
  if (
    !object(manifest) ||
    manifest.protocol !== 1 ||
    typeof manifest.module !== "string" ||
    typeof manifest.sha256 !== "string"
  )
    throw new Error("auth_keeper_bridge_manifest_invalid");
  const source = await ownedFile(manifest.module, false, "auth_keeper_bridge_module_unsafe");
  if (NodeCrypto.createHash("sha256").update(source).digest("hex") !== manifest.sha256)
    throw new Error("auth_keeper_bridge_pin_invalid");
  const loaded: unknown = NodeModule.createRequire(import.meta.url)(manifest.module);
  if (!object(loaded) || loaded.protocol !== 1 || typeof loaded.start !== "function")
    throw new Error("auth_keeper_bridge_protocol_invalid");
  const scoped: AuthKeeperBrowserCallbacks = {
    runtime: callbacks.runtime,
    withPage: (profileId, run) => {
      if (!managedProfiles.has(profileId))
        return Promise.reject(new Error("auth_keeper_bridge_profile_invalid"));
      return callbacks.withPage(profileId, run);
    },
    handoff: (input) => {
      if (!managedProfiles.has(input.profileId) || new URL(input.url).protocol !== "https:")
        return Promise.reject(new Error("auth_keeper_bridge_handoff_invalid"));
      return callbacks.handoff(input);
    },
    closeHandoff: (profileId) => {
      if (!managedProfiles.has(profileId))
        return Promise.reject(new Error("auth_keeper_bridge_profile_invalid"));
      return callbacks.closeHandoff(profileId);
    },
  };
  const result: unknown = await loaded.start({ ...scoped, manifestPath });
  if (!object(result) || typeof result.close !== "function")
    throw new Error("auth_keeper_bridge_lifecycle_invalid");
  const close = result.close as () => Promise<void>;
  if (
    !Array.isArray(result.profiles) ||
    result.profiles.length > 16 ||
    !result.profiles.every(
      (profile: unknown) =>
        isBrowserProfile(profile) &&
        profile.kind === "persistent" &&
        managedProfiles.has(profile.id),
    ) ||
    new Set(result.profiles.map((profile: BrowserProfile) => profile.id)).size !==
      result.profiles.length
  ) {
    await close();
    throw new Error("auth_keeper_bridge_profiles_invalid");
  }
  return { profiles: result.profiles as BrowserProfile[], close };
}
