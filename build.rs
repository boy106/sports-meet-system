//! 构建脚本：为授权模块生成**运行期数据**（v1.9.0 新增）。
//!
//! 生成两个文件到 `OUT_DIR`：
//!
//! 1. `keyfmt_secret.rs` —— 48 位密钥的主密钥（来源 `keys/aim.secret`，
//!    与 `keys/issuer.key` 同一保管级别，**绝不出现在任何交付包中**）。
//!    文件缺失时输出全零 + `CONFIGURED=false`，密钥激活整体停用
//!    （不影响程序其余功能，方便从源码二次开发）。
//! 2. `integrity_data.rs` —— 完整性自校验的期望段哈希（来源
//!    `target/integrity_cache.bin`，由 `tools/integrity_stamp.py`
//!    在发行构建的第二遍写入）。无缓存时输出**占位符 BLOB**
//!    （标志位 0 = 基线模式，只算不判）。
//!    注意：BLOB 必须是 `#[used] static` —— `const` 会被 LTO 折叠
//!    消除，数据区根本不会出现在二进制里（实测踩坑，见下方常量注释）。
//! 3. `issuer_pub.rs` —— Ed25519 签发公钥（来源 `keys/issuer.pub`）。
//!    缺失时全零 → 离线许可文件校验停用。
//!
//! # 为什么用"读取外部文件"而不是写死在源码里
//!
//! 源码包是交付物之一：任何写进 `.rs` 的秘密都会随源码包分发。
//! 把秘密放在 `keys/` 下（与 `issuer.key` 同级的私密文件），
//! 构建时读取、只进二进制，源码包里**没有**任何可用秘密。
//!
//! 掩码说明：主密钥以 `secret[i] ^ UNMASK[i]` 形式存放，
//! `UNMASK` 表在 `keyfmt.rs` 里（与生成文件分离）。这是混淆而非
//! 密码学保护 —— 真正的边界是"提取它需要完整逆向 + 绕过完整性自校验"。

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// 与 `src/core/aim/keyfmt.rs` 的 `UNMASK` 保持一致（改这里必须同步改那里）。
const UNMASK: [u8; 32] = [
    0x5a, 0x3c, 0x91, 0xe7, 0x0b, 0xd4, 0x68, 0x2f, 0xab, 0x13, 0x77, 0xc8, 0x4e, 0x9d, 0x21, 0xf6,
    0x8b, 0x54, 0x02, 0xbf, 0x6d, 0x31, 0xa9, 0x1c, 0xef, 0x47, 0x93, 0x25, 0xda, 0x08, 0x71, 0xc4,
];

/// 完整性数据区长度（与 integrity.rs 的 BLOB_LEN 一致）。
///
/// 布局（v1.9.0 修订，旧版 152 字节）：
/// ```text
///   [0..8)     起始魔数 "SMI1DATA"（同时是运行期的搜索锚）
///   [8..136)   8 段期望哈希（每段 16 字节）
///   [136..144) 8 个交叉指纹（相邻段异或后的字节和）
///   [144)      盖章标志：1 = 已盖章（真实期望值），0 = 基线（占位符）
///   [145..152) 保留（零）
///   [152..160) 结束魔数 "DATA1SMI"
/// ```
///
/// 为什么必须是 `#[used] static` 而不是 `const`：`const` 会被 LTO
/// 常量折叠掉（所有读取点都折成立即数，数组本身不再物化）——
/// 实测：折叠后二进制里只剩 `mask_blob` 自己的比较字面量，
/// 数据区根本不在文件里，盖章/复算全部无从谈起。
/// `#[used]` 把符号钉进 `llvm.compiler.used`，LTO 也会保留；
/// `#[link_section]` 给它独立节，避免被合并/截断。
/// 配合 integrity.rs 的 `read_volatile` 读取，两遍构建的**代码**
/// 完全相同（只有数据区 160 字节不同）—— 这是不动点的前提。
const BLOB_LEN: usize = 160;
const SEGMENTS: usize = 8;
const SEG_LEN: usize = 16;
const MAGIC_START: &[u8; 8] = b"SMI1DATA";
const MAGIC_END: &[u8; 8] = b"DATA1SMI";
/// 独立节名（与 integrity.rs 无关，仅用于把数据区隔离出来）。
const SECTION: &str = "sm_integrity";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    gen_keyfmt_secret(&out_dir, &manifest);
    gen_integrity_blob(&out_dir);
    gen_issuer_pub(&out_dir, &manifest);
    gen_devkey_fp(&out_dir, &manifest);
}

/// 演示开发者密钥（`THZX-2026-DEV`）的指纹 —— **仅 debug/test 构建回退用**。
///
/// v1.9.1 加固：发行（release）构建不再内置任何演示密钥。
/// 交付前把正式密钥指纹写入 `keys/devkey.fp`
/// （由 `sports-meet --devkey-fingerprint <新密钥>` 生成）。
const DEMO_DEVKEY_FINGERPRINT: &str = "35d041df2b141b66";

/// 生成 devkey_fp.rs（开发者模式密钥指纹）。
///
/// 来源 `keys/devkey.fp`：16 位小写十六进制，内容是 `--devkey` 明文经
/// `license::fingerprint` 计算的哈希（**不含明文**，见 `docs/12`）。
///
/// 缺失时的回退策略按 profile 区分：
/// * debug/test 构建 → 回退到演示指纹，保证 `cargo test` 与本地开发流程不中断；
/// * release 构建 → 空串：`License` 的常量时间比较永不相等，
///   开发者模式**整体停用** —— 发行包绝不内置可用密钥。
fn gen_devkey_fp(out_dir: &Path, manifest: &Path) {
    let fp_path = manifest.join("keys/devkey.fp");
    println!("cargo:rerun-if-changed={}", fp_path.display());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    let (fp, configured) = match fs::read_to_string(&fp_path) {
        Ok(text) => {
            let t = text.trim().to_lowercase();
            let ok = t.len() == 16 && t.chars().all(|c| c.is_ascii_hexdigit());
            if ok {
                (t, true)
            } else {
                println!(
                    "cargo:warning=keys/devkey.fp 不是 16 位十六进制指纹（开发者模式将停用）"
                );
                (String::new(), false)
            }
        }
        Err(_) => {
            if profile == "release" {
                println!(
                    "cargo:warning=未找到 keys/devkey.fp —— 发行构建的开发者模式已整体停用（这是预期加固行为；如需启用请先写入密钥指纹）"
                );
                (String::new(), false)
            } else {
                (DEMO_DEVKEY_FINGERPRINT.to_string(), true)
            }
        }
    };

    let mut src = String::with_capacity(512);
    src.push_str("// 由 build.rs 自动生成，请勿手工编辑。\n");
    src.push_str(&format!(
        "pub const DEVKEY_FINGERPRINT: &str = \"{}\";\n",
        fp
    ));
    src.push_str(&format!(
        "pub const DEVKEY_CONFIGURED: bool = {};\n",
        configured
    ));
    fs::write(out_dir.join("devkey_fp.rs"), src).expect("写 devkey_fp.rs 失败");
}

/// 生成 keyfmt_secret.rs（48 位密钥主密钥）。
fn gen_keyfmt_secret(out_dir: &Path, manifest: &Path) {
    let secret_path = manifest.join("keys/aim.secret");
    println!("cargo:rerun-if-changed={}", secret_path.display());

    let (masked, configured) = match fs::read_to_string(&secret_path) {
        Ok(text) => {
            let hex = text.trim();
            match hex_decode(hex) {
                Some(b) if b.len() == 32 => {
                    let m: Vec<u8> = (0..32).map(|i| b[i] ^ UNMASK[i]).collect();
                    (m, true)
                }
                _ => {
                    println!(
                        "cargo:warning=keys/aim.secret 内容不是 32 字节 hex（48 位密钥将停用）"
                    );
                    (vec![0u8; 32], false)
                }
            }
        }
        Err(_) => {
            println!(
                "cargo:warning=未找到 keys/aim.secret —— 48 位激活密钥校验已停用（源码开发不受影响；发行构建请先运行 tools/issue_license.py keygen-secret）"
            );
            (vec![0u8; 32], false)
        }
    };

    let mut src = String::with_capacity(1024);
    src.push_str("// 由 build.rs 自动生成，请勿手工编辑。\n");
    src.push_str(&format!(
        "pub const MASTER_MASKED: [u8; 32] = [{}];\n",
        masked
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    src.push_str(&format!("pub const CONFIGURED: bool = {};\n", configured));
    fs::write(out_dir.join("keyfmt_secret.rs"), src).expect("写 keyfmt_secret.rs 失败");
}

/// 生成 integrity_data.rs（完整性期望段哈希）。
fn gen_integrity_blob(out_dir: &Path) {
    // 缓存文件放在 target/ 下（跨构建存活；cargo clean 会清掉它，
    // 清掉后回到基线模式，需要重新盖章 —— 这正是想要的行为）。
    //
    // **按 profile 分开命名**：release 用 `integrity_cache.bin`
    // （`integrity_stamp.py` 的默认路径），其他 profile 用带后缀的名字。
    // 否则发行盖章后跑 `cargo test --release`，测试二进制会嵌入
    // "针对发行二进制的期望值" → 自校验必然失败 → 测试集体变红
    // （开发期 debug 构建永远读不到发行缓存，天然隔离）。
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let cache_name = if profile == "release" {
        "integrity_cache.bin".to_string()
    } else {
        format!("integrity_cache_{}.bin", profile)
    };
    let cache = target_dir(out_dir).join(&cache_name);
    println!("cargo:rerun-if-changed={}", cache.display());

    let (hashes, cross, flag): ([[u8; SEG_LEN]; SEGMENTS], [u8; SEGMENTS], u8) =
        match fs::read(&cache) {
            Ok(bytes) if bytes.len() == SEGMENTS * SEG_LEN + SEGMENTS => {
                // 有缓存 → "已盖章"：真实期望值
                let mut h = [[0u8; SEG_LEN]; SEGMENTS];
                for (i, seg) in h.iter_mut().enumerate() {
                    seg.copy_from_slice(&bytes[i * SEG_LEN..(i + 1) * SEG_LEN]);
                }
                let mut c = [0u8; SEGMENTS];
                c.copy_from_slice(&bytes[SEGMENTS * SEG_LEN..]);
                (h, c, 1)
            }
            _ => {
                // 无缓存 → 基线模式：占位符（确定性、非零）。
                // 非零是为了让交叉指纹校验在基线模式下同样成立
                // （运行期靠它排除"巧合出现的假数据区"）；
                // 占位符永不参与比对（标志位为 0 时跳过段哈希比较）。
                let mut h = [[0u8; SEG_LEN]; SEGMENTS];
                for (i, seg) in h.iter_mut().enumerate() {
                    for (j, b) in seg.iter_mut().enumerate() {
                        *b = ((i as u8).wrapping_mul(31))
                            .wrapping_add(j as u8)
                            .wrapping_mul(17)
                            ^ 0xA5;
                    }
                }
                let c = crosscheck(&h);
                (h, c, 0)
            }
        };

    let mut blob = [0u8; BLOB_LEN];
    blob[0..8].copy_from_slice(MAGIC_START);
    for (i, seg) in hashes.iter().enumerate() {
        blob[8 + i * SEG_LEN..8 + (i + 1) * SEG_LEN].copy_from_slice(seg);
    }
    blob[136..144].copy_from_slice(&cross);
    blob[144] = flag;
    blob[152..160].copy_from_slice(MAGIC_END);

    let mut src = String::with_capacity(2200);
    src.push_str("// 由 build.rs 自动生成，请勿手工编辑。\n");
    src.push_str("//\n");
    src.push_str("// 必须是 static + #[used] + #[link_section]：const 会被 LTO 折叠消除，\n");
    src.push_str("// 数据区就永远不在二进制里（盖章/复算/运行期校验全部失效）。\n");
    src.push_str("// 读取必须走 read_volatile（见 integrity.rs），否则期望值会被折成立即数，\n");
    src.push_str("// 两遍构建的代码就不一致，不动点被破坏。\n");
    src.push_str(&format!(
        "#[used]\n#[link_section = \"{}\"]\npub static BLOB: [u8; {}] = [{}];\n",
        SECTION,
        BLOB_LEN,
        blob.iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    fs::write(out_dir.join("integrity_data.rs"), src).expect("写 integrity_data.rs 失败");
}

/// 交叉指纹：第 i 个 = 第 i 段与第 i+1 段异或后的字节和（回绕）。
/// 与 integrity.rs 的 crosscheck() 公式必须一致。
fn crosscheck(segs: &[[u8; SEG_LEN]; SEGMENTS]) -> [u8; SEGMENTS] {
    let mut out = [0u8; SEGMENTS];
    for i in 0..SEGMENTS {
        let a = &segs[i];
        let b = &segs[(i + 1) % SEGMENTS];
        let mut acc: u8 = 0;
        for k in 0..SEG_LEN {
            acc = acc.wrapping_add(a[k] ^ b[k]);
        }
        out[i] = acc;
    }
    out
}

/// 生成 issuer_pub.rs（Ed25519 签发公钥）。
fn gen_issuer_pub(out_dir: &Path, manifest: &Path) {
    let pub_path = manifest.join("keys/issuer.pub");
    println!("cargo:rerun-if-changed={}", pub_path.display());

    let (pk, configured) = match fs::read_to_string(&pub_path) {
        Ok(text) => match hex_decode(text.trim()) {
            Some(b) if b.len() == 32 => (b, true),
            _ => {
                println!("cargo:warning=keys/issuer.pub 内容不是 32 字节 hex（离线许可文件校验将停用）");
                (vec![0u8; 32], false)
            }
        },
        Err(_) => {
            println!(
                "cargo:warning=未找到 keys/issuer.pub —— Ed25519 离线许可校验已停用（源码开发不受影响；发行构建请先运行 tools/issue_license.py keygen）"
            );
            (vec![0u8; 32], false)
        }
    };

    let mut src = String::with_capacity(1024);
    src.push_str("// 由 build.rs 自动生成，请勿手工编辑。\n");
    src.push_str(&format!(
        "pub const ISSUER_PUBLIC_KEY: [u8; 32] = [{}];\n",
        pk.iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    src.push_str(&format!("pub const ISSUER_KEY_CONFIGURED: bool = {};\n", configured));
    fs::write(out_dir.join("issuer_pub.rs"), src).expect("写 issuer_pub.rs 失败");
}

/// 从 OUT_DIR 向上找到 `target/` 目录。
fn target_dir(out_dir: &Path) -> PathBuf {
    let mut p = out_dir.to_path_buf();
    loop {
        if p.file_name().map(|n| n == "target").unwrap_or(false) {
            return p;
        }
        if !p.pop() {
            // 找不到就退回 OUT_DIR 的祖父目录（尽力而为）
            return out_dir.to_path_buf();
        }
    }
}

/// 解析 hex 字符串（允许空白与换行）。
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}
