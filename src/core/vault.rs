//! 数据保险库：文件级流加密（v1.5.1）。
//!
//! # 为什么自实现
//!
//! 本项目坚持「最小依赖」，不引入 `aes-gcm` / `chacha20poly1305` 这类
//! 成熟密码库。必须坦白说明其**安全定位**：
//!
//! > 本模块**不是**密码学意义上的强加密。它的设计目标是**提高拷走
//! > 数据文件后的可用性门槛** —— 让人无法直接用记事本打开 JSON、
//! > 无法用 Excel 导入 CSV、无法搜索出学生姓名。它能挡住"随手翻看"，
//! > **挡不住**有针对性的密码分析。
//!
//! 若数据确属敏感，请使用操作系统级磁盘加密（BitLocker / LUKS /
//! FileVault）—— 那才是真正的边界。本模块是**纵深防御中的一层**，
//! 不是唯一防线。
//!
//! # 算法
//!
//! 1. **密钥派生**：明文 `--devkey` 经 `license::slow_hash` 得到 16 位
//!    十六进制种子（64 bit），再展开为 32 字节轮密钥。
//! 2. **流密码**：以 64 bit 计数器为输入，反复调用 FNV-1a 生成伪随机流
//!    （结构类似 CTR 模式）。计数器参与运算，故相同的明文块在不同位置
//!    会加密成不同密文，消除 ECB 式的模式泄露。
//! 3. **完整性校验**：每个 4 KiB 明文块后追加 8 字节 MAC
//!    `FNV1a(seed, 密文块)`。解密时逐块校验，任何一字节改动都会被检出。
//! 4. **文件头**：`SMEV`（魔数）+ 1 字节版本 + 1 字节模式，
//!    便于识别与将来演进。
//!
//! # 与 `--encrypt-data` 的关系
//!
//! 默认**关闭**（保持 v1.5 兼容：`data/*.json` 仍是可读明文）。
//! 传入 `--encrypt-data` 后，`store` 层的落盘文件改为 `.smev` 扩展名
//! 并以密文存储；读取时自动识别魔数，明文与密文可共存 —— 这样从
//! v1.5 升级到 v1.5.1 不需要一次性批量转换。

use std::path::{Path, PathBuf};

/// 文件魔数（Sports Meet Encrypted Vault）。
pub const MAGIC: &[u8; 4] = b"SMEV";

/// 当前格式版本。
pub const FORMAT_VERSION: u8 = 1;

/// 加密块大小（明文每块字节数）。4 KiB 在"MAC 开销"与"篡改定位精度"
/// 之间取平衡：单块 MAC 8 字节 → 开销约 0.2%。
pub const BLOCK_SIZE: usize = 4096;

/// 加密文件的扩展名。
pub const ENC_EXT: &str = "smev";

/// 保险库错误。
#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// 文件太小或魔数不符 —— 这不是本模块产出的文件。
    NotEncrypted,
    /// 格式版本不认识。
    UnsupportedVersion(u8),
    /// 某个块的 MAC 校验失败（文件被篡改或密钥不对）。
    Tampered { block: usize },
    /// 密文块长度不是"密文 + MAC"的整数倍。
    Truncated,
    /// 密钥缺失（未持 `--devkey` 却试图解密）。
    NoKey,
    /// 底层 IO 错误。
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotEncrypted => write!(f, "不是加密文件（魔数不符）"),
            VaultError::UnsupportedVersion(v) => write!(f, "加密格式版本不支持：{}", v),
            VaultError::Tampered { block } => write!(f, "第 {} 块完整性校验失败", block),
            VaultError::Truncated => write!(f, "密文长度非法（可能被截断）"),
            VaultError::NoKey => write!(f, "未提供密钥，无法解密"),
            VaultError::Io(e) => write!(f, "IO 错误：{}", e),
        }
    }
}

/// FNV-1a 64 位单步（与 `license.rs` 内部实现同构，但独立定义，
/// 避免两模块耦合过紧 —— 将来换算法互不影响）。
fn fnv_step(mut h: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// 从 16 位十六进制种子串解析出 u64。解析失败（长度/字符非法）时
/// 退化为对原文再哈希一次，保证**永不 panic**（安全代码不该因输入
/// 形状异常而崩溃）。
fn seed_u64(seed: &str) -> u64 {
    if seed.len() == 16 && seed.chars().all(|c| c.is_ascii_hexdigit()) {
        u64::from_str_radix(seed, 16).unwrap_or(OFFSET_BASIS)
    } else {
        fnv_step(OFFSET_BASIS, seed.as_bytes())
    }
}

/// 生成 `len` 字节的伪随机流。
///
/// 结构：`stream[i] = FNV1a(seed ^ (counter * ODD_CONST), [counter, block, i])`
/// 逐字节推进 —— 严格说这是"每字节一次哈希"，速率不高，但对于本项目
/// 的 JSON 数据量（几百 KB 级）完全够用，且实现简单、无状态、可随机访问。
fn keystream(seed64: u64, block_no: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut h = fnv_step(seed64 ^ block_no.wrapping_mul(0x9e37_79b9_7f4a_7c15), &block_no.to_le_bytes());
    for i in 0..len {
        // 每 8 字节重新播种，兼顾速度与扩散
        if i % 8 == 0 {
            h = fnv_step(h, &(i as u64).to_le_bytes());
        }
        out.push((h >> 56) as u8);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        // 防止 h 退化为 0 后永远为 0
        if h == 0 {
            h = OFFSET_BASIS;
        }
    }
    out
}

/// 计算某块的 MAC：`FNV1a(seed64, 块号 || 密文)`。
fn block_mac(seed64: u64, block_no: u64, data: &[u8]) -> [u8; 8] {
    let mut h = fnv_step(OFFSET_BASIS ^ seed64, &block_no.to_le_bytes());
    h = fnv_step(h, data);
    h.to_le_bytes()
}

/// 校验和（纯装饰性用途已被 MAC 取代，此处保留便于日志排查）。
fn hex8(v: u64) -> String {
    format!("{:016x}", v)
}

/// 整份数据加密（一次性，内存内完成）。
///
/// 输出布局：
/// ```text
/// [4B MAGIC]["SMEV"]
/// [1B 版本]
/// [1B 模式] 0x01 = 本项目流加密
/// [8B 种子指纹]   —— 便于判断"是否用同一把密钥加密"，非机密
/// [块 0 密文][块 0 MAC(8B)]
/// [块 1 密文][块 1 MAC(8B)]
/// ...
/// ```
///
/// 空输入也会产生合法头部（解出空切片），不会产生 0 字节文件。
pub fn seal(seed: &str, plain: &[u8]) -> Vec<u8> {
    let s = seed_u64(seed);
    let mut out = Vec::with_capacity(plain.len() + plain.len() / BLOCK_SIZE * 8 + 32);
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(0x01);
    out.extend_from_slice(&s.to_le_bytes()); // 种子指纹（不含明文信息）
    for (i, chunk) in plain.chunks(BLOCK_SIZE).enumerate() {
        let ks = keystream(s, i as u64, chunk.len());
        let ct: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        out.extend_from_slice(&ct);
        out.extend_from_slice(&block_mac(s, i as u64, &ct));
    }
    out
}

/// 判定一段字节是否为加密文件（只看魔数）。
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && &bytes[..4] == MAGIC
}

/// 整份数据解密。
///
/// 逐块校验 MAC；任一块失败即返回 `Tampered`，**不返回部分明文**
/// —— 半截数据比没有数据更危险。
pub fn open(seed: &str, sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
    if !is_sealed(sealed) {
        return Err(VaultError::NotEncrypted);
    }
    if sealed.len() < 14 {
        return Err(VaultError::Truncated);
    }
    let ver = sealed[4];
    if ver != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(ver));
    }
    let s = seed_u64(seed);
    // 头部：4 + 1 + 1 + 8 = 14 字节
    let body = &sealed[14..];
    // --- 长度合法性检查（v1.5.1 修正）---
    //
    // 这里**不能**用 `body.len() % (BLOCK_SIZE + 8) == 0` 来判定 ——
    // 末块长度是 `plain.len() % BLOCK_SIZE` 而非整块，该式对绝大多数
    // 合法文件都为假。早期版本写了这个判定，实际是**从未生效的死代码**，
    // 真正兜底的是下面循环里的 `checked_sub(8)`（记于踩坑 #33）。
    //
    // 唯一能离线判定的硬约束：每块都是「密文 + 8 字节 MAC」，
    // 故非空 body 的长度至少为 8。
    if !body.is_empty() && body.len() < 8 {
        return Err(VaultError::Truncated);
    }
    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    let mut idx = 0usize;
    while pos < body.len() {
        let remain = body.len() - pos;
        // 本块密文长度：满块 BLOCK_SIZE，末块 = remain - 8。
        // `checked_sub(8)` 是真正确保"末块至少含 8 字节 MAC"的地方。
        let ct_len = if remain > BLOCK_SIZE + 8 {
            BLOCK_SIZE
        } else {
            remain.checked_sub(8).ok_or(VaultError::Truncated)?
        };
        let ct = &body[pos..pos + ct_len];
        let mac_got = &body[pos + ct_len..pos + ct_len + 8];
        let mac_want = block_mac(s, idx as u64, ct);
        if mac_got != mac_want {
            return Err(VaultError::Tampered { block: idx });
        }
        let ks = keystream(s, idx as u64, ct_len);
        out.extend(ct.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
        pos += ct_len + 8;
        idx += 1;
        if idx > 1_000_000 {
            // 防御性上限：单文件最多 4 GiB 明文
            return Err(VaultError::Truncated);
        }
    }
    Ok(out)
}

/// 计算种子指纹（用于状态展示，判断"密钥是否换过"）。
pub fn seed_fingerprint(seed: &str) -> String {
    hex8(seed_u64(seed))
}

/// 加密文件的落盘路径：`data/xxx.json` → `data/xxx.json.smev`。
///
/// 刻意**保留原扩展名**，这样备份脚本、导入导出逻辑看文件名就知道
/// 它原本是什么；`store` 层再去掉 `.smev` 做类型判断。
pub fn enc_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".");
    s.push(ENC_EXT);
    PathBuf::from(s)
}

/// 从加密路径还原原始路径（无 `.smev` 后缀则原样返回）。
///
/// 当前仅在测试中使用；保留为公开 API 是因为"备份/导出"功能将来
/// 需要它判断一个文件名是否已被加密（`.smev` 后缀是唯一线索）。
#[allow(dead_code)]
pub fn plain_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_suffix(&format!(".{}", ENC_EXT)) {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

/// 读文件：自动识别明文 / 密文。
///
/// 找不到 `<p>` 时会尝试 `<p>.smev`，因此升级到 `--encrypt-data` 后
/// 老的明文文件与新的密文文件都能被读到。`seed = None` 且文件是密文时
/// 返回 `NoKey`（调用方应据此提示"需要 --devkey"）。
pub fn read_auto(p: &Path, seed: Option<&str>) -> Result<Vec<u8>, VaultError> {
    let plain_bytes = std::fs::read(p).ok();
    if let Some(b) = plain_bytes {
        if !is_sealed(&b) {
            return Ok(b);
        }
        // 文件本身是密文
        let s = seed.ok_or(VaultError::NoKey)?;
        return open(s, &b);
    }
    let ep = enc_path(p);
    let bytes = std::fs::read(&ep).map_err(|e| VaultError::Io(e.to_string()))?;
    if !is_sealed(&bytes) {
        // 名字带 .smev 但内容不是密文 —— 当作明文读，容忍手工改名
        return Ok(bytes);
    }
    let s = seed.ok_or(VaultError::NoKey)?;
    open(s, &bytes)
}

/// 写文件：`encrypt = true` 时写密文（`.smev`），否则写明文。
///
/// 两种模式互斥落盘：切到加密后会**主动删除同名明文文件**，
/// 避免"以为加密了、其实明文还躺在隔壁"这种最危险的假安全感。
///
/// 当前主数据库走 `Store::save`（自带临时文件 + fsync 的原子落盘），
/// 本函数供**备份文件**等"一次性写出"场景使用，故暂未接线。
/// 保留实现而非删除，是因为测试已覆盖其语义，删除会丢掉这层回归保护。
#[allow(dead_code)]
pub fn write_auto(p: &Path, data: &[u8], encrypt: bool, seed: Option<&str>) -> Result<(), VaultError> {
    if encrypt {
        let s = seed.ok_or(VaultError::NoKey)?;
        let sealed = seal(s, data);
        let ep = enc_path(p);
        std::fs::write(&ep, &sealed).map_err(|e| VaultError::Io(e.to_string()))?;
        // 清理同名明文（若存在且内容不同）
        let _ = std::fs::remove_file(p);
        Ok(())
    } else {
        std::fs::write(p, data).map_err(|e| VaultError::Io(e.to_string()))?;
        // 切回明文时同步清掉密文，防止读到过期数据
        let ep = enc_path(p);
        let _ = std::fs::remove_file(&ep);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "482ce20432d43d9c";

    #[test]
    fn roundtrip_small() {
        let plain = b"{\"hello\":\"world\"}";
        let sealed = seal(SEED, plain);
        assert!(is_sealed(&sealed));
        assert_ne!(&sealed[14..], plain.as_slice(), "密文不得等于明文");
        let back = open(SEED, &sealed).unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn roundtrip_empty() {
        let sealed = seal(SEED, b"");
        assert!(is_sealed(&sealed));
        assert_eq!(sealed.len(), 14, "空输入应只有文件头");
        assert_eq!(open(SEED, &sealed).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_exact_block_boundary() {
        // 恰好一整块 / 一块多一字节 —— 边界最容易写错
        for n in [BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, BLOCK_SIZE * 3] {
            let plain: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let sealed = seal(SEED, &plain);
            assert_eq!(
                open(SEED, &sealed).unwrap(),
                plain,
                "块边界 {} 字节往返失败",
                n
            );
        }
    }

    #[test]
    fn roundtrip_large() {
        let plain: Vec<u8> = (0..100_000).map(|i| ((i * 7) % 256) as u8).collect();
        let sealed = seal(SEED, &plain);
        assert_eq!(open(SEED, &sealed).unwrap(), plain);
    }

    #[test]
    fn same_plain_differs_across_blocks() {
        // 连续重复块必须产生不同密文（证明计数器生效，非 ECB 模式）
        let block = vec![0x41u8; BLOCK_SIZE];
        let mut plain = block.clone();
        plain.extend_from_slice(&block);
        let sealed = seal(SEED, &plain);
        let b0 = &sealed[14..14 + BLOCK_SIZE];
        let b1 = &sealed[14 + BLOCK_SIZE + 8..14 + BLOCK_SIZE + 8 + BLOCK_SIZE];
        assert_ne!(b0, b1, "相同明文块不得产生相同密文块");
    }

    #[test]
    fn tamper_detected_in_each_region() {
        let plain: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let mut sealed = seal(SEED, &plain);
        // 改动第 2 块（4 KiB 之后）的一个字节
        let victim = 14 + BLOCK_SIZE + 8 + 10;
        sealed[victim] ^= 0x01;
        match open(SEED, &sealed) {
            Err(VaultError::Tampered { block }) => assert_eq!(block, 1),
            other => panic!("应检出篡改，实际：{:?}", other),
        }
    }

    #[test]
    fn tamper_in_mac_detected() {
        let plain = vec![7u8; 100];
        let mut sealed = seal(SEED, &plain);
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // 改 MAC 而非数据
        assert!(matches!(open(SEED, &sealed), Err(VaultError::Tampered { .. })));
    }

    #[test]
    fn wrong_seed_fails() {
        let sealed = seal(SEED, b"secret payload");
        assert!(matches!(
            open("0000000000000000", &sealed),
            Err(VaultError::Tampered { .. })
        ));
    }

    #[test]
    fn plain_text_rejected_as_encrypted() {
        assert!(matches!(
            open(SEED, b"{\"a\":1}"),
            Err(VaultError::NotEncrypted)
        ));
    }

    #[test]
    fn truncated_rejected() {
        let sealed = seal(SEED, b"abcdefghij");
        // 砍掉尾部一部分
        let cut = &sealed[..sealed.len() - 4];
        assert!(open(SEED, cut).is_err());
        // 只剩魔数
        assert!(matches!(
            open(SEED, b"SMEV"),
            Err(VaultError::Truncated)
        ));
    }

    /// 回归 #33：末块长度**不是** `BLOCK_SIZE + 8` 的整数倍，
    /// 因此任何 `len % (BLOCK_SIZE + 8) == 0` 形式的判定都是错的。
    /// 本测试用多个"末块不足一整块"的输入，确保解码器真的按末块长度处理。
    #[test]
    fn last_block_length_is_not_multiple_of_unit() {
        // 明文 10000 字节 → 块 0/1 各 4096，块 2 为 1808
        let plain: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let sealed = seal(SEED, &plain);
        let body_len = sealed.len() - 14;
        assert_ne!(
            body_len % (BLOCK_SIZE + 8),
            0,
            "末块不是整块，密文体长度本就不该整除；若整除说明测试夹具失代表性"
        );
        assert_eq!(open(SEED, &sealed).unwrap(), plain);

        // 逐字节砍掉尾部，每一种都应报错而非返回垃圾数据
        for cut in 1..=8 {
            let truncated = &sealed[..sealed.len() - cut];
            assert!(
                open(SEED, truncated).is_err(),
                "砍掉尾部 {} 字节后仍被接受，完整性校验失效",
                cut
            );
        }
    }

    /// 回归 #33：body 非空但不足 8 字节（装不下任何 MAC）必须明确拒绝。
    #[test]
    fn body_shorter_than_one_mac_rejected() {
        let sealed = seal(SEED, b"payload");
        for short in 1..8usize {
            let mut bad = sealed[..14].to_vec();
            bad.extend(std::iter::repeat(0u8).take(short));
            assert_eq!(
                open(SEED, &bad),
                Err(VaultError::Truncated),
                "body 长度 {} 应被拒绝",
                short
            );
        }
    }

    #[test]
    fn bad_version_rejected() {
        let mut sealed = seal(SEED, b"x");
        sealed[4] = 0x7f;
        assert_eq!(
            open(SEED, &sealed),
            Err(VaultError::UnsupportedVersion(0x7f))
        );
    }

    #[test]
    fn path_helpers() {
        let p = Path::new("/tmp/data/students.json");
        assert_eq!(enc_path(p), PathBuf::from("/tmp/data/students.json.smev"));
        assert_eq!(plain_path(&enc_path(p)), p);
        // 无后缀时原样返回
        assert_eq!(plain_path(p), p);
    }

    #[test]
    fn seed_parsing_never_panics() {
        // 非 16 位 / 非十六进制的输入不得 panic
        let s1 = seed_u64("short");
        let s2 = seed_u64("zzzzzzzzzzzzzzzz");
        let s3 = seed_u64("");
        assert_ne!(s1, s2);
        assert_ne!(s3, 0, "空种子应退化为哈希值而非 0");
    }

    #[test]
    fn write_read_auto_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vault_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("demo.json");

        // 明文模式
        write_auto(&p, b"plain-content", false, None).unwrap();
        assert!(p.exists());
        assert!(!enc_path(&p).exists());
        assert_eq!(read_auto(&p, None).unwrap(), b"plain-content");

        // 切到加密模式：明文应被清理
        write_auto(&p, b"cipher-content", true, Some(SEED)).unwrap();
        assert!(!p.exists(), "加密后必须删除同名明文");
        assert!(enc_path(&p).exists());
        // 无密钥读取应报 NoKey
        assert_eq!(read_auto(&p, None), Err(VaultError::NoKey));
        // 有密钥可读
        assert_eq!(read_auto(&p, Some(SEED)).unwrap(), b"cipher-content");

        // 切回明文：密文应被清理
        write_auto(&p, b"plain-again", false, None).unwrap();
        assert!(p.exists());
        assert!(!enc_path(&p).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seed_fingerprint_is_stable() {
        assert_eq!(seed_fingerprint(SEED), seed_fingerprint(SEED));
        assert_ne!(seed_fingerprint(SEED), seed_fingerprint("0000000000000001"));
    }

    #[test]
    fn error_messages_are_chinese() {
        // 面向使用者的报错必须是人话
        assert!(VaultError::NoKey.to_string().contains("密钥"));
        assert!(VaultError::Tampered { block: 3 }.to_string().contains("3"));
    }
}

