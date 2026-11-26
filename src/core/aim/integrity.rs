//! 二进制完整性自校验 + 分散互校验（v1.9.0 新增 · 手段 2）。
//!
//! # 解决什么问题
//!
//! 攻击者常用手法是**直接改二进制**：把"未授权"分支改成跳转、把校验函数
//! 改成 `return true`。只要他改成功，所有授权逻辑形同虚设。
//!
//! 本模块让"改二进制"这件事**变得难以成功**：
//!
//! 1. **自校验**：运行期读自身可执行文件，对**除嵌入数据区以外的全部字节**
//!    分段算 SHA-512，与编译期嵌入的期望值比对。改任何一个字节 →
//!    对应段哈希不符 → 拒绝授权（并留下可观测的失败）。
//! 2. **分散**：期望值不是一个大常量，而是**切成 8 段**、每段独立比对，
//!    且各段之间**交叉校验**（见 [`crosscheck`]）—— 攻击者想改就得
//!    同时找对并改对全部 8 段 + 交叉指纹。
//! 3. **多重调用**：`verify_self()` 在授权判定、HTTP 门禁、诊断状态
//!    多处被调用，任一处不符即失败，不存在"找到唯一 check 函数并
//!    patch 掉"的捷径（与手段 3 协同）。
//!
//! # 诚实声明（必读）
//!
//! 纯客户端自校验**不可能做到绝对**。能反编译并 patch 校验逻辑的人，
//! 也能 patch 掉"自校验失败后的处理"。本模块的作用是：
//!
//! * **抬高门槛**：从"改一个字节"变成"定位并改 8 段分散常量 + 校验逻辑"；
//! * **增加暴露面**：任何不一致都会在经过的**任一处**触发，
//!   留下可观测的失败（配合日志/上报可追溯）。
//!
//! 它**挡不住**有能力完整重写校验的人。这是所有纯客户端方案的共同宿命，
//! 与 `docs/13` 第七节立场一致。
//!
//! # 为什么能自洽（嵌入期望值 vs 改了就变）
//!
//! "期望值来自二进制自身"有一个经典悖论：把期望值嵌进二进制，
//! 二进制就变了，哈希又对不上了。解法是**掩码**：
//!
//! ```text
//!   编译期（build.rs）生成 160 字节的数据区（BLOB）：
//!     [0..8)     起始魔数 "SMI1DATA"
//!     [8..136)   8 段期望哈希（每段 16 字节）
//!     [136..144) 8 个交叉指纹
//!     [144)      盖章标志（1 = 已盖章，0 = 基线）
//!     [145..152) 保留（零）
//!     [152..160) 结束魔数 "DATA1SMI"
//!   运行期/盖章期：先在文件里定位起始魔数（锚就取自 BLOB 自身，
//!   因此二进制里这个魔数**只出现一次**），把 [pos, pos+160) 整段掩码
//!   归零，再对**剩余全部字节**分 8 段算哈希。
//!
//!   同时还要把 GNU build-id 笔记的 desc 归零（见坑 3）。
//! ```
//!
//! 因为"被嵌定期望值"与"被掩码掉的内容"是**同一段字节**，
//! 嵌入真实期望值（第二遍构建）不会改变掩码后的内容 —— 哈希达到不动点。
//!
//! # 两个踩过的坑（v1.9.0 实测，改动本文件前必读）
//!
//! 1. **BLOB 必须是 `#[used] static`，不能是 `const`**。
//!    `const` 数组的所有读取点都是常量索引 → LTO 直接把数组折叠消除，
//!    二进制里只剩 `mask_blob` 自己的比较字面量（实测两者相距 104 字节），
//!    数据区根本不在文件里，盖章/复算全部失效。
//!    `#[used]`（进 `llvm.compiler.used`）+ `#[link_section]`（独立节）
//!    保证它原样物化；生成文件里的属性见 build.rs。
//! 2. **读取必须走 `read_volatile`**。否则期望值会被折成立即数嵌进
//!    比较指令：第一遍（占位符）与第二遍（真实值）编译出的**代码不同**，
//!    掩码后文件仍然不同 —— 不动点被破坏，`--verify` 永远红。
//!    volatile 读取让两遍构建的代码完全一致，只有数据区那 160 字节不同。
//! 3. **必须连 GNU build-id 笔记一起掩码**。链接器默认给每个二进制写
//!    `.note.gnu.build-id`（20 字节），它是**对全部节内容算的哈希**：
//!    BLOB 内容两遍构建间不同 → build-id 不同 → 那 20 字节也随 BLOB
//!    变化 → 只掩码 BLOB 仍达不到不动点（实测：段 0 复算永远不符，
//!    且报错信息完全不提示真正原因）。笔记头（namesz/descsz/type/name）
//!    是静态的不用动，只归零 desc 即可（见 [`mask_build_id`]）。
//!
//! 数据区魔数找不到（首次构建 / 开发期 / 从源码自行构建），或标志位为 0
//! （基线）时，模块自动进入**基线模式**（只算不判），不影响 `cargo test`
//! 与二次开发。
//!
//! ⚠️ **盖章后不要跑 `cargo test --release`**：release profile 与发行
//! 共用 `target/integrity_cache.bin`，测试二进制会嵌入"针对发行二进制的
//! 期望值" → 自校验不符 → 相关测试变红（自解释的失败信息里写明解法）。
//! 开发期测试请用 `cargo test`（debug，缓存名天然隔离）；
//! 发行包始终走 `build.sh`。
//!
//! # 发行构建流程（build.sh）
//!
//! ```text
//!   ① cargo build --release        （BLOB 占位符 + 标志 0 → 基线模式）
//!   ② tools/integrity_stamp.py     算期望值写 target/integrity_cache.bin
//!   ③ touch build.rs && cargo build --release   （嵌入真实期望值 + 标志 1）
//!   ④ tools/integrity_stamp.py --verify        复算比对，必须一致
//! ```

#![allow(dead_code)]

use crate::core::aim::asym::sha512;

mod expected {
    include!(concat!(env!("OUT_DIR"), "/integrity_data.rs"));
}

/// 分散段数。每段独立哈希、独立存放、交叉比对。
pub const SEGMENTS: usize = 8;

/// 段哈希长度（SHA-512 前 16 字节）。
pub const SEG_LEN: usize = 16;

/// 数据区总长度（字节）：魔数(8) + 段哈希(128) + 交叉指纹(8) + 标志(1)
/// + 保留(7) + 结束魔数(8)。
const BLOB_LEN: usize = 160;
/// 段哈希在数据区内的偏移。
const OFF_HASHES: usize = 8;
/// 交叉指纹在数据区内的偏移。
const OFF_CROSS: usize = 136;
/// 盖章标志在数据区内的偏移（1 = 已盖章，0 = 基线）。
const OFF_FLAG: usize = 144;
/// 结束魔数在数据区内的偏移。
const OFF_END: usize = 152;
/// 已盖章标志值。
const FLAG_STAMPED: u8 = 1;

/// 自校验结果。
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    /// 是否通过（基线模式下恒为 true）。
    pub passed: bool,
    /// 是否为基线模式（二进制里没有数据区魔数）。
    pub baseline: bool,
    /// 实际算出的段哈希（每段 SEG_LEN 字节）。
    pub actual: Vec<[u8; SEG_LEN]>,
    /// 与期望不符的段号。
    pub mismatches: Vec<usize>,
    /// 是否成功读到自身二进制。
    pub self_read_ok: bool,
    /// 交叉校验是否通过。
    pub crosscheck_ok: bool,
}

impl IntegrityReport {
    pub fn summary(&self) -> String {
        if !self.self_read_ok {
            return "完整性：无法读取自身二进制（未校验）".to_string();
        }
        if self.baseline {
            // 发行构建里"基线"= 未按发行流程盖章，授权不可信（见 status_json_fields）；
            // debug 构建（开发/自测）没有期望值可比，才是真的"不阻断"。
            return if cfg!(debug_assertions) {
                "完整性：基线模式（未嵌入期望值，不阻断）".to_string()
            } else {
                "完整性：基线模式（发行版未嵌入期望值，授权不可信）".to_string()
            };
        }
        if !self.passed && self.mismatches.is_empty() {
            return "完整性：数据区定位失败（起始魔数被破坏或数据区被挪走）".to_string();
        }
        if self.passed && self.crosscheck_ok {
            "完整性：校验通过".to_string()
        } else if !self.crosscheck_ok {
            "完整性：交叉校验失败（期望数据自身不一致）".to_string()
        } else {
            format!(
                "完整性：{} 段校验失败 {:?}",
                self.mismatches.len(),
                self.mismatches
            )
        }
    }

    /// 是否构成"必须拒绝授权"的失败。
    ///
    /// 只有**非基线 + 读到了自身 + 校验不过**才致命：
    /// 读不到自身文件时不能误杀（ exotic 平台/容器限制），
    /// 基线模式（自行编译）本就无期望值可比。
    pub fn is_fatal(&self) -> bool {
        self.self_read_ok && !self.baseline && (!self.passed || !self.crosscheck_ok)
    }
}

/// 读取自身可执行文件内容。
fn read_self() -> Option<Vec<u8>> {
    // Linux：/proc/self/exe 是最可靠的路径（不受 argv[0] 伪造影响）
    #[cfg(target_os = "linux")]
    {
        if let Ok(data) = std::fs::read("/proc/self/exe") {
            return Some(data);
        }
    }
    // 回退：current_exe()
    if let Ok(p) = std::env::current_exe() {
        if let Ok(data) = std::fs::read(&p) {
            return Some(data);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 嵌入数据区的访问（全部走 read_volatile）
// ---------------------------------------------------------------------------

/// 读数据区的第 `i` 字节（volatile：阻止 LTO 把期望值折成立即数）。
///
/// 这不是性能优化遗漏，而是**正确性要求**：若允许折叠，第一遍构建
/// （占位符）与第二遍构建（真实值）会产出不同的比较指令，
/// 掩码后的文件就不一致 —— 两遍构建的不动点被破坏（见模块文档坑 2）。
fn blob_byte(i: usize) -> u8 {
    debug_assert!(i < BLOB_LEN);
    unsafe { core::ptr::read_volatile((&expected::BLOB as *const _ as *const u8).add(i)) }
}

/// 读数据区的一个区段（volatile）。
fn blob_slice(off: usize, len: usize) -> Vec<u8> {
    (off..off + len).map(blob_byte).collect()
}

/// 数据区自身的起始魔数（运行期搜索锚）。
/// 刻意**不**用源码里的字面量当锚：那个字面量本身也会在二进制里出现一次，
/// 搜索时会先撞上它（实测两者相距 104 字节，结束魔数校验必然失败）。
/// 从 BLOB 里读锚 → 二进制里这个魔数只存在数据区一处，搜索无歧义。
fn blob_magic_start() -> [u8; 8] {
    let mut m = [0u8; 8];
    m.copy_from_slice(&blob_slice(0, 8));
    m
}

/// 数据区自身的结束魔数。
fn blob_magic_end() -> [u8; 8] {
    let mut m = [0u8; 8];
    m.copy_from_slice(&blob_slice(OFF_END, 8));
    m
}

/// 编译期兜底魔数（v1.9.1 加固第二层）。
///
/// 与 BLOB 里的值必须一致（`blob_layout_constants` 测试会校验）。
/// 用途：当 BLOB 里的魔数被抹成全零时（BLOB 本身被破坏），
/// 用这两个常量继续定位——否则"锚全零 + 结束魔数全零"会自我确认，
/// 命中一个错位候选后算出**未掩码**的段哈希，反而报"校验通过"。
/// 常量本身会在二进制里出现，但只在兜底路径使用，
/// 且必须同时满足"交叉指纹自洽"，误命中概率仍是 2^-64 量级。
const MAGIC_START_FALLBACK: &[u8; 8] = b"SMI1DATA";
const MAGIC_END_FALLBACK: &[u8; 8] = b"DATA1SMI";

/// 数据区里的段哈希区是否满足交叉指纹（用于在文件里识别真假数据区）。
///
/// 假候选（别处恰好出现的 8 字节）要通过这个检查的概率是 2^-64。
fn cross_consistent(hashes: &[u8], cross: &[u8]) -> bool {
    if hashes.len() != SEGMENTS * SEG_LEN || cross.len() != SEGMENTS {
        return false;
    }
    for i in 0..SEGMENTS {
        let a = &hashes[i * SEG_LEN..(i + 1) * SEG_LEN];
        let b = &hashes[((i + 1) % SEGMENTS) * SEG_LEN..(((i + 1) % SEGMENTS) + 1) * SEG_LEN];
        let mut acc: u8 = 0;
        for k in 0..SEG_LEN {
            acc = acc.wrapping_add(a[k] ^ b[k]);
        }
        if acc != cross[i] {
            return false;
        }
    }
    true
}

/// 把二进制里的 GNU build-id 笔记 desc 归零（内容派生，破坏不动点）。
///
/// `.note.gnu.build-id` 是链接器对**全部节内容**算的哈希：BLOB 内容
/// 在两遍构建间不同 → build-id 不同 → 文件里那 16/20/32 字节随 BLOB
/// 一起变化 → 只掩码 BLOB 仍达不到不动点（实测段 0 复算永远不符）。
/// 把 desc 归零后，两遍构建的内容才真正只差"被掩码掉的那 160 字节"。
///
/// 笔记布局（小端）：`[namesz=4][descsz][type=3]["GNU\0"][desc...]`。
/// 只归零 desc；笔记头是静态的（两遍构建相同），不用动。
/// 匹配条件刻意收紧（namesz==4 且 0<descsz<=64），假阳性会顺带掩盖
/// 一段内容 → 哈希不符 → `--verify` 响亮失败，不会静默放过。
fn mask_build_id(data: &mut [u8]) {
    let mut from = 0usize;
    while from + 8 <= data.len() {
        let Some(rel) = data[from..].windows(8).position(|w| {
            w[0] == 3
                && w[1] == 0
                && w[2] == 0
                && w[3] == 0
                && w[4] == b'G'
                && w[5] == b'N'
                && w[6] == b'U'
                && w[7] == 0
        }) else {
            return;
        };
        let p = from + rel; // type 字段位置；name 在 p+4，desc 在 p+8
        if p >= 8 {
            let namesz = u32::from_le_bytes([data[p - 8], data[p - 7], data[p - 6], data[p - 5]]) as usize;
            let descsz = u32::from_le_bytes([data[p - 4], data[p - 3], data[p - 2], data[p - 1]]) as usize;
            if namesz == 4 && descsz > 0 && descsz <= 64 {
                let end = (p + 8 + descsz).min(data.len());
                for b in &mut data[p + 8..end] {
                    *b = 0;
                }
            }
        }
        from = p + 8; // 本候选处理完（合格/不合格都继续找下一处）
    }
}

/// 在二进制里定位数据区并掩码归零。
///
/// 返回 `Some(pos)` 表示找到了数据区（`pos` = 数据区起始偏移）；
/// `None` 表示没找到（基线构建 / 开发期 / 自行编译）。
///
/// 定位策略：锚取自 BLOB 自身的魔数（见 [`blob_magic_start`]），
/// 逐个候选校验「结束魔数 + 交叉指纹」—— 双保险排除巧合命中。
/// 命中后把数据区与 build-id desc 一起归零（后者是内容派生的，
/// 见 [`mask_build_id`]）。
fn mask_blob(data: &mut [u8]) -> Option<usize> {
    let mut anchor = blob_magic_start();
    let mut end_magic = blob_magic_end();
    // v1.9.1 加固（第二层）：两个魔数都从 BLOB 读，**同一个攻击会同时污染两者** ——
    // 抹掉起始魔数后结束魔数往往也被抹（都在数据区里），此时一旦命中就是
    // "锚全零 + 结束魔数全零"的自我确认，等于没有校验。
    // 所以：锚或结束魔数为全零（结构上不可能是合法魔数）时，
    // 退回编译期常量兜底。
    if anchor == [0u8; 8] || end_magic == [0u8; 8] {
        anchor = *MAGIC_START_FALLBACK;
        end_magic = *MAGIC_END_FALLBACK;
    }
    // v1.9.1 加固（第一层）：`last = true` —— 取**最后一个**合格候选。
    //
    // 漏洞成因（实测复现）：攻击者把起始魔数改成 0 → 锚变成 8 个零字节 →
    // PE 数据区前后的零填充里到处是这个"锚"，而候选位置的结束魔数/交叉指纹
    // 仍指向**真实数据区**，于是第一个零字节候选就"达标"了。
    // 掩码被错位 → 段哈希算的是**未掩码的裸数据** → 8 段全"一致" →
    // 攻击者把魔数抹掉反而换来一个"校验通过"的绿色状态。
    //
    // 真实数据区在结构上是候选段的最后一段（后面只剩尾部零填充），
    // 所以取最后一个合格候选能拿回正确位置；其余候选一律不认。
    mask_blob_with(data, &anchor, &end_magic, true)
}

/// 定位与掩码的**可注入版本**：允许指定锚与结束魔数。
///
/// 生产路径只用 [`mask_blob`]；本函数存在的意义是让测试能注入
/// "BLOB 被破坏后实际会看到的那组值"（全零锚 + 兜底结束魔数），
/// 以及给反向验证（旧逻辑取第一个候选）留出对照实现的空间。
fn mask_blob_with(data: &mut [u8], anchor: &[u8; 8], end_magic: &[u8; 8], last: bool) -> Option<usize> {
    if data.len() < BLOB_LEN {
        return None;
    }
    let mut hit = None;
    let mut from = 0usize;
    while from + 8 <= data.len() {
        let Some(rel) = data[from..].windows(8).position(|w| w == anchor.as_slice()) else {
            break;
        };
        let pos = from + rel;
        let end = pos + BLOB_LEN;
        if end <= data.len()
            && &data[pos + OFF_END..pos + OFF_END + 8] == end_magic.as_slice()
            && cross_consistent(
                &data[pos + OFF_HASHES..pos + OFF_HASHES + SEGMENTS * SEG_LEN],
                &data[pos + OFF_CROSS..pos + OFF_CROSS + SEGMENTS],
            )
        {
            hit = Some(pos);
            if !last {
                break; // 旧行为：取第一个
            }
        }
        from = pos + 1;
    }
    if let Some(pos) = hit {
        for b in &mut data[pos..pos + BLOB_LEN] {
            *b = 0;
        }
        mask_build_id(data);
    }
    hit
}

/// 把（已掩码的）二进制均分为 8 段，取每段 SHA-512 前 16 字节。
fn segment_hashes(data: &[u8]) -> Vec<[u8; SEG_LEN]> {
    let n = data.len();
    (0..SEGMENTS)
        .map(|i| {
            let s = i * n / SEGMENTS;
            let e = (i + 1) * n / SEGMENTS;
            let h = sha512(&data[s..e]);
            let mut seg = [0u8; SEG_LEN];
            seg.copy_from_slice(&h[..SEG_LEN]);
            seg
        })
        .collect()
}

/// 从嵌入数据区取出 8 段期望哈希（volatile 读，见 [`blob_byte`]）。
fn expected_segments() -> [[u8; SEG_LEN]; SEGMENTS] {
    let mut out = [[0u8; SEG_LEN]; SEGMENTS];
    for i in 0..SEGMENTS {
        for (k, b) in out[i].iter_mut().enumerate() {
            *b = blob_byte(OFF_HASHES + i * SEG_LEN + k);
        }
    }
    out
}

/// 数据区是否"已盖章"（标志位为 1）。基线构建 → false。
fn is_stamped() -> bool {
    blob_byte(OFF_FLAG) == FLAG_STAMPED
}

/// 执行一次完整性自校验。
///
/// 基线模式下（数据区标志位为 0，或根本没找到数据区）返回 `passed=true`，
/// 只报 actual 供诊断。
pub fn verify_self() -> IntegrityReport {
    let Some(mut data) = read_self() else {
        return IntegrityReport {
            passed: true,
            baseline: true,
            actual: Vec::new(),
            mismatches: Vec::new(),
            self_read_ok: false,
            crosscheck_ok: true,
        };
    };
    let pos = mask_blob(&mut data);
    // 标志位为 0 → 基线（占位符不比对）
    if !is_stamped() {
        return IntegrityReport {
            passed: true,
            baseline: true,
            actual: Vec::new(),
            mismatches: Vec::new(),
            self_read_ok: true,
            crosscheck_ok: true,
        };
    }
    // v1.9.1 加固：**标志位是 1（声称已盖章）却没定位到数据区** —— 这不是基线，
    // 而是"数据区被破坏/挪走"的攻击形态（例如抹掉起始魔数让搜索锚失效）。
    // 旧实现会掉进下面"未掩码裸数据"的分支继续比对，结论完全不可信，
    // 且打印的摘要会误导排查。现在直接判失败（基线探测要靠标志位，见上一条）。
    if pos.is_none() {
        return IntegrityReport {
            passed: false,
            baseline: false,
            actual: Vec::new(),
            mismatches: Vec::new(),
            self_read_ok: true,
            crosscheck_ok: true, // 交叉校验无从谈起，交由 passed=false 定性
        };
    }
    let actual = segment_hashes(&data);
    let exp = expected_segments();
    let mut mismatches = Vec::new();
    for (i, e) in exp.iter().enumerate() {
        match actual.get(i) {
            Some(a) if a == e => {}
            _ => mismatches.push(i),
        }
    }
    IntegrityReport {
        passed: mismatches.is_empty(),
        baseline: false,
        actual,
        mismatches,
        self_read_ok: true,
        crosscheck_ok: crosscheck(),
    }
}

/// 分散互校验：校验嵌入数据区自身的内部一致性。
///
/// 第 i 个交叉指纹 = 第 i 段与第 i+1 段异或后的字节和。
/// 作用：攻击者若把某段期望哈希改掉（或整区清零），
/// 交叉指纹对不上 → 即使该段"看起来通过了"，交叉校验也会失败。
pub fn crosscheck() -> bool {
    let segs = expected_segments();
    for i in 0..SEGMENTS {
        let a = &segs[i];
        let b = &segs[(i + 1) % SEGMENTS];
        let mut mix = [0u8; SEG_LEN];
        for k in 0..SEG_LEN {
            mix[k] = a[k] ^ b[k];
        }
        let want = blob_byte(OFF_CROSS + i);
        let got: u8 = mix.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        if got != want {
            return false;
        }
    }
    true
}

/// 一致性状态摘要（供诊断接口 / 授权判定使用）。
pub fn status_json_fields() -> (bool, bool, String) {
    let r = verify_self();
    let s = r.summary();
    // v1.9.1 加固：与 `recheck_gate()` 的判定保持**同一口径**。
    // 发行构建里"基线模式"意味着期望值没被嵌进来（构建流程被绕开），
    // 授权不可信 —— 必须在这里也报 ok=false，否则诊断页显示"ok:true"
    // 而接口实际被拦，排查时会得出完全相反的结论。
    let baseline_untrusted = !crate::core::aim::OPEN_SOURCE && !cfg!(debug_assertions) && r.baseline;
    (!(r.is_fatal() || baseline_untrusted), r.baseline, s)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个"有效"的数据区：魔数取自内嵌 BLOB 自身（与运行期同源），
    /// 交叉指纹按 `crosscheck` 公式算全。用于喂给 `mask_blob` 做定位测试。
    fn make_blob(hashes: &[[u8; SEG_LEN]; SEGMENTS], flag: u8) -> [u8; BLOB_LEN] {
        let mut b = [0u8; BLOB_LEN];
        b[0..8].copy_from_slice(&blob_magic_start());
        for (i, seg) in hashes.iter().enumerate() {
            b[OFF_HASHES + i * SEG_LEN..OFF_HASHES + (i + 1) * SEG_LEN].copy_from_slice(seg);
        }
        for i in 0..SEGMENTS {
            let a = &hashes[i];
            let n = &hashes[(i + 1) % SEGMENTS];
            let mut acc: u8 = 0;
            for k in 0..SEG_LEN {
                acc = acc.wrapping_add(a[k] ^ n[k]);
            }
            b[OFF_CROSS + i] = acc;
        }
        b[OFF_FLAG] = flag;
        b[OFF_END..OFF_END + 8].copy_from_slice(&blob_magic_end());
        b
    }

    /// 确定性伪随机段哈希（避免各段相同导致假阳性）。
    fn pseudo_hashes(seed: u8) -> [[u8; SEG_LEN]; SEGMENTS] {
        let mut out = [[0u8; SEG_LEN]; SEGMENTS];
        for (i, seg) in out.iter_mut().enumerate() {
            for (k, b) in seg.iter_mut().enumerate() {
                *b = ((i as u8).wrapping_mul(seed))
                    .wrapping_add(k as u8)
                    .wrapping_mul(17)
                    ^ 0xA5;
            }
        }
        out
    }

    /// 在 data[off] 处放一个 GNU build-id 笔记（小端头 + desc）。
    fn put_fake_build_id(data: &mut [u8], off: usize, desc: &[u8]) {
        data[off..off + 4].copy_from_slice(&4u32.to_le_bytes()); // namesz
        data[off + 4..off + 8].copy_from_slice(&(desc.len() as u32).to_le_bytes()); // descsz
        data[off + 8..off + 12].copy_from_slice(&3u32.to_le_bytes()); // type=NT_GNU_BUILD_ID
        data[off + 12..off + 16].copy_from_slice(b"GNU\0");
        data[off + 16..off + 16 + desc.len()].copy_from_slice(desc);
    }

    #[test]
    fn blob_layout_constants() {
        assert_eq!(BLOB_LEN, 160);
        assert_eq!(OFF_HASHES, 8);
        assert_eq!(OFF_CROSS, 136);
        assert_eq!(OFF_FLAG, 144);
        assert_eq!(OFF_END, 152);
        // 各区不重叠、不越界
        assert!(OFF_HASHES + SEGMENTS * SEG_LEN <= OFF_CROSS);
        assert!(OFF_CROSS + SEGMENTS <= OFF_FLAG);
        assert!(OFF_END + 8 == BLOB_LEN);
        assert_eq!(blob_magic_start().len(), 8);
        assert_eq!(blob_magic_end().len(), 8);
        assert_ne!(blob_magic_start(), blob_magic_end());
        // 兜底常量必须与 BLOB 内的值一致（改一处必须同步改另一处）
        assert_eq!(&blob_magic_start(), MAGIC_START_FALLBACK);
        assert_eq!(&blob_magic_end(), MAGIC_END_FALLBACK);
    }

    #[test]
    fn segment_split_covers_all_bytes() {
        // 用确定性伪随机内容（全同字节会让各段哈希撞车，那是输入问题不是切分问题）
        let mut data = vec![0u8; 8000];
        let mut x: u32 = 0x1234_5678;
        for b in data.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        let segs = segment_hashes(&data);
        assert_eq!(segs.len(), SEGMENTS);
        // 每段内容不同（首段是 [0,1000)，其余 [1000*i, ...)）→ 哈希两两不同
        for i in 0..SEGMENTS {
            for j in (i + 1)..SEGMENTS {
                assert_ne!(segs[i], segs[j], "段 {} 与段 {} 内容应不同", i, j);
            }
        }
    }

    #[test]
    fn mask_finds_and_zeroes_blob() {
        let mut data = vec![0x11u8; 4096];
        let blob = make_blob(&pseudo_hashes(31), FLAG_STAMPED);
        data.extend_from_slice(&blob);
        data.extend_from_slice(&[0x22u8; 100]);
        let pos = mask_blob(&mut data).expect("应能找到数据区");
        assert_eq!(pos, 4096);
        // 数据区被清零，其余不动
        assert!(data[pos..pos + BLOB_LEN].iter().all(|&b| b == 0));
        assert!(data[..pos].iter().all(|&b| b == 0x11));
        assert!(data[pos + BLOB_LEN..].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn mask_picks_last_when_anchor_is_zeroed() {
        // v1.9.1 加固回归测试（实测复现过的真实攻击）。
        //
        // 实测攻击：把数据区的**起始魔数** 8 字节改成 0。此后运行期从 BLOB
        // 读到的锚就是 8 个零字节，而段哈希/交叉指纹/结束魔数全都还在原位。
        // 数据区前面是大片零填充（PE 的 .text 尾部、ELF 的占位区），
        // 于是「零锚 + 仍在原位的结束魔数 + 自洽的交叉指纹」会同时命中
        // **多个**位置：第一个是错位的零字节位置，最后一个是真实数据区。
        // 旧实现取第一个 → 掩错位置 → 段哈希算在未掩码的裸数据上 →
        // 8 段全"相符" → 攻击者抹掉魔数反而换来一个绿色状态。
        let hs = pseudo_hashes(41);
        let mut data = vec![0u8; 8192];
        // 数据区贴近文件尾部（与真实二进制一致：后面只剩很短的尾部填充）
        let real = 7900usize;
        // 不能用 make_blob：它的魔数取自 BLOB 自身，而本用例模拟的正是
        // "BLOB 已被破坏"，必须用编译期常量构造。
        let mut blob = [0u8; BLOB_LEN];
        blob[0..8].copy_from_slice(MAGIC_START_FALLBACK);
        for (i, seg) in hs.iter().enumerate() {
            blob[OFF_HASHES + i * SEG_LEN..OFF_HASHES + (i + 1) * SEG_LEN].copy_from_slice(seg);
        }
        for i in 0..SEGMENTS {
            let a = &hs[i];
            let n = &hs[(i + 1) % SEGMENTS];
            let mut acc: u8 = 0;
            for k in 0..SEG_LEN {
                acc = acc.wrapping_add(a[k] ^ n[k]);
            }
            blob[OFF_CROSS + i] = acc;
        }
        blob[OFF_FLAG] = FLAG_STAMPED;
        blob[OFF_END..OFF_END + 8].copy_from_slice(MAGIC_END_FALLBACK);
        // 攻击：只抹起始魔数（结束魔数留在尾部，这正是能重新定位的依据）
        blob[0..8].copy_from_slice(&[0u8; 8]);
        data[real..real + BLOB_LEN].copy_from_slice(&blob);

        // 前提校验：这个构造必须真的出现"多个零锚候选"，否则用例没有区分度
        let cands: Vec<usize> = (0..data.len() - BLOB_LEN)
            .filter(|&i| {
                data[i..i + 8] == [0u8; 8]
                    && &data[i + OFF_END..i + OFF_END + 8] == MAGIC_END_FALLBACK
                    && cross_consistent(
                        &data[i + OFF_HASHES..i + OFF_HASHES + SEGMENTS * SEG_LEN],
                        &data[i + OFF_CROSS..i + OFF_CROSS + SEGMENTS],
                    )
            })
            .collect();
        assert_eq!(cands.last(), Some(&real), "最后一个候选应是真实数据区");
        // 注：这里只要 ≥1 个候选就够验证"命中正确位置"；
        // "多候选 → 取第一个会错位" 这条漏洞链在真实 PE 上已实测复现
        // （见 docs/09_交付清单.md 17.8），synthetic 数据无法稳定重现
        // PE 零填充区的具体字节分布，不在此强行构造。

        // 新行为（取最后一个）：命中真实数据区
        let mut new = data.clone();
        let got = mask_blob_with(&mut new, &[0u8; 8], MAGIC_END_FALLBACK, true);
        assert_eq!(got, Some(real), "必须命中真实数据区，不能是错位候选");
        assert!(
            new[real..real + BLOB_LEN].iter().all(|&b| b == 0),
            "真实数据区必须被掩码归零"
        );
    }

    #[test]
    fn mask_rejects_incomplete_magic() {
        let mut data = vec![0u8; 4096];
        // 只有起始魔数、没有结束魔数与交叉指纹 → 不算数据区
        data[100..108].copy_from_slice(&blob_magic_start());
        assert!(mask_blob(&mut data).is_none());
    }

    #[test]
    fn mask_rejects_inconsistent_crosscheck() {
        let mut data = vec![0x44u8; 2048];
        let mut blob = make_blob(&pseudo_hashes(37), FLAG_STAMPED);
        blob[OFF_CROSS + 3] ^= 0xFF; // 破坏一个交叉指纹
        data.extend_from_slice(&blob);
        data.extend_from_slice(&[0x55u8; 64]);
        assert!(
            mask_blob(&mut data).is_none(),
            "交叉指纹不符的候选必须拒绝（假阳性排除）"
        );
    }

    #[test]
    fn mask_is_stable_under_reembed() {
        // 模拟两遍构建：第一遍占位符（标志 0），第二遍真实期望值（标志 1）——
        // 掩码后内容必须一致（不动点）。这正是发行流程 ①③ 两步的前提。
        // 同时放入**不同 desc 的 build-id 笔记**（链接器对内容算哈希，
        // BLOB 变了它也跟着变）—— 掩码必须连它一起归零，否则不动点不成立。
        let mut pass1 = vec![0x33u8; 5000];
        pass1.extend_from_slice(&make_blob(&pseudo_hashes(31), 0)); // 基线占位符
        put_fake_build_id(&mut pass1, 100, &[0x11; 20]);
        let mut pass2 = pass1.clone();
        pass2[5000..5000 + BLOB_LEN].copy_from_slice(&make_blob(&pseudo_hashes(53), FLAG_STAMPED));
        put_fake_build_id(&mut pass2, 100, &[0x99; 20]); // 不同 build-id

        assert!(mask_blob(&mut pass1).is_some(), "占位符结构完整 → 能找到");
        assert!(mask_blob(&mut pass2).is_some(), "真实值 → 能找到");
        assert_eq!(pass1, pass2, "掩码后两遍构建必须字节一致（不动点）");
    }

    #[test]
    fn mask_zeroes_build_id_note() {
        let mut data = vec![0x66u8; 4096];
        put_fake_build_id(&mut data, 100, &[0xAB; 20]);
        mask_build_id(&mut data);
        // desc 归零，笔记头保持（头是静态的）
        assert!(data[116..136].iter().all(|&b| b == 0), "build-id desc 必须归零");
        assert_eq!(&data[100..116], &[4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0]);
        // 其余字节不动
        assert!(data[..100].iter().all(|&b| b == 0x66));
        assert!(data[136..].iter().all(|&b| b == 0x66));
    }

    #[test]
    fn mask_build_id_ignores_bogus_note() {
        // namesz≠4 的"GNU\0"型笔记不是 build-id，不能掩（也不该崩）
        let mut data = vec![0x77u8; 512];
        data[200..204].copy_from_slice(&9u32.to_le_bytes()); // namesz=9
        data[204..208].copy_from_slice(&20u32.to_le_bytes());
        data[208..212].copy_from_slice(&3u32.to_le_bytes());
        data[212..216].copy_from_slice(b"GNU\0");
        data[216..236].copy_from_slice(&[0xAB; 20]);
        mask_build_id(&mut data);
        assert!(data[216..236].iter().all(|&b| b == 0xAB), "非 build-id 笔记不掩");
    }

    #[test]
    fn stamped_but_unlocatable_blob_is_fatal() {
        // v1.9.1 加固回归测试。
        // 攻击形态：标志位声称"已盖章"，但起始魔数被抹掉 → 搜索锚失效 →
        // `mask_blob` 返回 None。若此时还退化成"未掩码裸数据比对"，
        // 结论毫无意义；必须直接判失败。
        //
        // 直接构造一个报告以隔离断言（`verify_self` 读的是磁盘上的真实二进制，
        // 无法在单测里伪造）。这里校验判定函数本身的口径：
        let r = IntegrityReport {
            passed: false,
            baseline: false,
            actual: Vec::new(),
            mismatches: Vec::new(),
            self_read_ok: true,
            crosscheck_ok: true,
        };
        assert!(r.is_fatal(), "盖章却定位失败必须致命");
        assert!(r.summary().contains("数据区定位失败"), "摘要应点明定位失败");
        // 对照：真正的基线（标志位 0 / 没盖章）不算致命
        let base = IntegrityReport {
            baseline: true,
            passed: true,
            ..r.clone()
        };
        assert!(!base.is_fatal(), "基线不是 is_fatal（由调用方按发行/调试区分）");
        // 且调试构建下基线的摘要不出现"不可信"字样
        assert!(!base.summary().contains("定位失败"));
    }

    #[test]
    fn status_fields_match_gate_semantics() {
        // v1.9.1 加固回归测试：诊断接口与授权门禁必须同一口径。
        // 发行构建里 baseline 视为不可信 → ok 必须为 false；
        // debug 构建（单测即此情形）没有期望值可比 → ok 为 true。
        let (ok, base, _) = status_json_fields();
        if !cfg!(debug_assertions) && base {
            assert!(!ok, "发行构建的基线模式必须在诊断里报 ok=false");
        }
        if cfg!(debug_assertions) {
            assert!(ok, "debug 构建的自校验不应影响 ok");
        }
    }

    #[test]
    fn verify_self_runs_without_panic() {
        let r = verify_self();
        let _ = r.summary();
        // 测试构建没有盖章数据 → 基线模式，恒通过。
        // 唯一的例外：**发行盖章之后跑了 `cargo test --release`** ——
        // release profile 与发行共用缓存名（build.rs），测试二进制会
        // 嵌入"针对发行二进制的期望值"，自校验必然不符。这是**故意的
        // 响亮失败**（宁可红，也不能让测试二进制假装通过），下面给出
        // 自解释的失败信息与解法。
        if !r.baseline && !r.passed && is_stamped() {
            panic!(
                "测试二进制嵌入了针对**发行二进制**的期望值（盖章后跑了 cargo test --release）。\n\
                 解法：rm -f target/integrity_cache.bin 后重跑；或改用 cargo test（debug profile 缓存隔离）。\n\
                 发行包请始终用 build.sh 构建，它自己管缓存生命周期。"
            );
        }
        assert!(r.baseline || r.passed);
        if r.baseline {
            assert!(r.passed);
            assert!(r.mismatches.is_empty());
        }
    }

    #[test]
    fn crosscheck_ok_on_placeholder_blob() {
        // 开发/测试构建：build.rs 生成的占位符自带一致的交叉指纹
        assert!(crosscheck());
    }

    #[test]
    fn test_build_is_never_stamped() {
        // profile=test 的缓存名与 release 隔离（见 build.rs），发行盖章
        // 写进的是 target/integrity_cache.bin，测试构建永远读不到 →
        // 恒为基线。若此断言红，说明缓存隔离失效（或跑了 --release），
        // 测试会嵌入发行期望值 → 自校验集体变红。
        assert!(
            !is_stamped(),
            "测试构建不应该是已盖章状态。若刚跑过 build.sh，请用 cargo test（debug）\
             而非 cargo test --release —— release profile 与发行共用 integrity_cache.bin。"
        );
    }
}
