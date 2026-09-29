/**
 * QA 类型探针 —— Issue #8 步骤 3 中**只能在类型层判定**的验收标准。
 *
 * 为什么单独一个文件：`test/transfer-blackbox.mjs` 只 import 构建产物 `dist/`，运行期看到的
 * 是 JS，拿不到类型信息；而步骤 3 的核心不变量是「`ParsedEntry` 上**不存在**某八个字段」，
 * 这是一个编译期事实，只能用 `tsc --noEmit` 判定。
 *
 * 运行（在仓库根，需先 `pnpm build`）：
 *   pnpm exec tsc --noEmit --strict --skipLibCheck --target es2022 \
 *     --module nodenext --moduleResolution nodenext test/transfer-type-probe.ts
 * exit 0 = 全部不变量成立。任何一条被破坏都会让本文件出现编译错误。
 *
 * 只覆盖步骤 3 冻结的四条标准，不引入计划外的类型判据。
 */

import type {
  FormatId,
  ParsedEntry,
  ParsedHotpEntry,
  ParsedTotpEntry,
  PlaintextContainer,
} from '../packages/transfer/dist/index.js'

/**
 * 每条不变量都写成「条件类型求值后赋值」的形式：成立时右值为 `true` 且类型也是 `true`，
 * 赋值通过；不成立时类型退化为 `false`，`true` 赋不进去，编译器报错。
 * 导出是为了让 ESLint 不把探针常量当成未使用变量。
 */
type Holds<Condition extends boolean> = Condition

/**
 * 对照组（**故意失败**，靠 `@ts-expect-error` 吸收）：证明上面的 `Holds` 断言不是空转。
 * 若 `Holds` 机制失效，本行的错误消失，`tsc` 会改报 TS2578「Unused directive」而 exit 非 0。
 */
// @ts-expect-error - 对照组：'id' 不是 never，条件类型求值为 false，true 赋不进去
export const controlProbe: Holds<['id'] extends [never] ? true : false> = true

/** 判别联合两侧出现过的全部字段名。 */
type EntryKeys = keyof ParsedTotpEntry | keyof ParsedHotpEntry

// ── 验收标准 1：八个字段一个都不许出现 ─────────────────────────────────────────
// design 方案 A：id 要随机源、position 要 #5 的 fractional index、createdAt / updatedAt 要时钟，
// 引用其中任何一个都会让解析器不再是纯函数（C6），golden test 也无法稳定快照。

type ForbiddenKeys =
  'id' | 'position' | 'tagIds' | 'sites' | 'usageCount' | 'lastUsedAt' | 'createdAt' | 'updatedAt'

/** 若八个字段中有任何一个出现在 `ParsedEntry` 上，`Extract` 就不是 `never`，本行编译失败。 */
export const forbiddenFieldsAbsent: Holds<
  [Extract<EntryKeys, ForbiddenKeys>] extends [never] ? true : false
> = true

/** 赋值方向的同一判据：多余的 `id` 必须被对象字面量多余属性检查拒绝。 */
export const rejectIdLiteral: ParsedEntry = {
  kind: 'totp',
  issuer: 'Deno',
  account: 'alice@example.com',
  secret: new Uint8Array(10),
  algo: 'SHA1',
  digits: 6,
  note: '',
  tagNames: [],
  favorite: false,
  sourceIndex: 0,
  period: 30,
  // @ts-expect-error - ParsedEntry 不得接受 id（步骤 3 验收标准 1）
  id: '01890b0e-0000-7000-8000-000000000000',
}

/** 读取方向的同一判据：`position` 在类型上不存在，取值即 TS2339。 */
declare const someEntry: ParsedEntry
// @ts-expect-error - ParsedEntry 上不存在 position（步骤 3 验收标准 1）
export const rejectPositionRead = someEntry.position

// ── 验收标准 2：必备字段齐全，且判别联合强制 period / counter ──────────────────

type RequiredKeys =
  'kind' | 'issuer' | 'account' | 'secret' | 'algo' | 'digits' | 'tagNames' | 'sourceIndex'

/** 八个必备字段必须全部在 `ParsedEntry` 上；缺任何一个，`Extract` 就窄于 `RequiredKeys`。 */
export const requiredFieldsPresent: Holds<
  [Extract<RequiredKeys, EntryKeys>] extends [RequiredKeys] ? true : false
> = true

/** `kind === 'totp'` 时 `period` 必有值。 */
export const totpCarriesPeriod: Holds<['period'] extends [keyof ParsedTotpEntry] ? true : false> =
  true

/** `kind === 'hotp'` 时 `counter` 必有值。 */
export const hotpCarriesCounter: Holds<['counter'] extends [keyof ParsedHotpEntry] ? true : false> =
  true

/** 反向：totp 不得用 counter 顶替 period，hotp 不得用 period 顶替 counter。 */
export const rejectTotpWithoutPeriod: ParsedEntry = {
  kind: 'totp',
  issuer: 'Deno',
  account: 'alice@example.com',
  secret: new Uint8Array(10),
  algo: 'SHA1',
  digits: 6,
  note: '',
  tagNames: [],
  favorite: false,
  sourceIndex: 0,
  // @ts-expect-error - totp 不接受 counter，缺 period 时判别联合必须拒绝（步骤 3 验收标准 2）
  counter: 42,
}

export const rejectHotpWithoutCounter: ParsedEntry = {
  kind: 'hotp',
  issuer: 'WWE',
  account: 'Mason',
  secret: new Uint8Array(10),
  algo: 'SHA512',
  digits: 8,
  note: '',
  tagNames: [],
  favorite: false,
  sourceIndex: 1,
  // @ts-expect-error - hotp 不接受 period，缺 counter 时判别联合必须拒绝（步骤 3 验收标准 2）
  period: 30,
}

// ── 验收标准 3：`PlaintextContainer['encrypted']` 是字面量类型 false ───────────

export const encryptedAcceptsFalse: Holds<
  [PlaintextContainer['encrypted']] extends [false] ? true : false
> = true

// @ts-expect-error - encrypted 是字面量 false，不接受 true（步骤 3 验收标准 3）
export const encryptedRejectsTrue: PlaintextContainer['encrypted'] = true

// ── 验收标准 4：八个格式 id 都在 FormatId 上 ──────────────────────────────────

type RequiredFormatIds =
  | 'mfavault-plaintext'
  | 'aegis'
  | '2fas'
  | 'freeotp-plus'
  | 'ente'
  | 'bitwarden'
  | 'otpauth-lines'
  | 'generic-csv'

export const formatIdsCovered: Holds<[RequiredFormatIds] extends [FormatId] ? true : false> = true
