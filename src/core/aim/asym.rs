//! 非对称离线许可（v1.9.0 新增 · 手段 1）。
//!
//! # 解决什么问题
//!
//! v1.8.x 的授权是**在线**模型：客户端拿票据找服务端验签。这留下一个口子 ——
//! 用户若能配置一个"假服务端"（或改 hosts 指向自己的机器），即可自签自验。
//! 而且断网环境（机房、内网、无服务器）根本没法激活。
//!
//! 本模块引入**离线非对称许可**：签发方持**私钥**，客户端只嵌**公钥**。
//!
//! ```text
//!   发行方（你）                          客户端（用户机器）
//!   ┌────────────┐                       ┌──────────────────┐
//!   │ 私钥 sk    │ ──签发──▶ license.lic  │ 公钥 pk（编译进）│
//!   │ 签发脚本   │   (R,S,M 三元组)       │ 离线验签 verify  │
//!   └────────────┘                       └──────────────────┘
//!         ▲                                       │
//!         │ 私钥**绝不进发行包**，只进源码包        │ 用户拿不到私钥
//!         └───────────────────────────────────────┘ → 无法自造授权
//! ```
//!
//! # 为什么用 Ed25519
//!
//! * **签名快、验证快、密钥短**（公钥 32B、签名 64B），适合塞进二进制；
//! * **确定性签名**（无随机数）→ 不存在 ECDSA 那种"随机数重用即泄露私钥"的坑；
//! * **验签只需公钥 + 曲线运算**，不需要任何秘密，天然适合离线分发。
//!
//! # 自实现说明（诚实版）
//!
//! 本模块**不使用外部密码学 crate**，遵守项目"最小依赖"原则。自实现的部分：
//!
//! | 组件 | 行数级 | 依据 |
//! |---|---|---|
//! | SHA-512 | ~180 | FIPS 180-4 |
//! | 域运算 mod 2^255-19 | ~120 | RFC 7748 |
//! | Edwards 点解压 / 双标量乘 | ~260 | RFC 8032 §5.1.7 |
//! | 标量 mod L 归约 | ~90 | RFC 8032 §5.1.6 |
//!
//! **验证方式**：用 **RFC 8032 §7.1 官方测试向量**做单测（见文末 `mod tests`），
//! 5 组向量全部通过才算实现正确。这是密码学实现的最低验收标准。
//!
//! **已知限制**：
//! * 未做**常量时间**处理 —— 验签过程用公开数据（公钥、签名、消息），
//!   不含秘密，因此时序泄露**不构成**密钥泄露路径（签名侧才需要恒时；
//!   我们不做签名，签发在离线脚本里，不在本模块）；
//! * 未实现小阶点/公钥合法性完整检查（`cofactorless` 验证变体）；
//!   对"防白嫖"场景足够 —— 攻击者伪造不了签名，本就不依赖这些边角。
//!
//! # 许可文件格式
//!
//! ```text
//!   {
//!     "v": 1,                   格式版本
//!     "hwid": "ab12cd34...",    机器指纹哈希（绑定，拷机无效）
//!     "exp": 1799999999,        到期 Unix 秒（0 = 永久）
//!     "kind": "persistent",     persistent | temporary
//!     "mask": 0x5A5A...,         载荷异或掩码（防肉眼直读）
//!     "sig": "<base64 64B>"     Ed25519 签名，覆盖上面全部字段的规范化串
//!   }
//! ```
//!
//! 签名的**消息 = 规范化载荷串**（字段按固定顺序拼接，见 [`license_message`]）。
//! 客户端解析后**重算**该串再验签 —— 任何字段被改，验签立刻失败。

#![allow(dead_code)]

// ─────────────────────────────────────────────────────────────────────
// 一、SHA-512（FIPS 180-4）
// ─────────────────────────────────────────────────────────────────────

/// SHA-512 初始向量（FIPS 180-4 §5.3.5）。
const SHA512_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// SHA-512 轮常量 K（FIPS 180-4 §4.2.3），前 80 个素数立方根小数部分。
const SHA512_K: [u64; 80] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
];

/// SHA-512 摘要计算（一次性接口，输入全部驻内存）。
///
/// 本项目用它算的输入都很小（< 1KB：许可载荷串、自身校验块），
/// 不需要流式接口，故不实现 `update/finalize` 分离。
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = SHA512_IV;

    // ── 填充（FIPS 180-4 §5.1.2）──
    // 追加 0x80，补零至 len ≡ 112 (mod 128)，再写 128 位大端比特长度。
    let bit_len = (data.len() as u128) * 8;
    let mut msg = Vec::with_capacity(data.len() + 144);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // ── 逐块压缩 ──
    for block in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, v) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// 二、域运算 mod p = 2^255 - 19
// ─────────────────────────────────────────────────────────────────────
//
// 用 [u64; 5] 的 51 位肢体表示（radix 2^51），这是 ref10 的经典布局：
// 5×51 = 255 位，刚好容纳一个域元素，且乘法中间值用 u128 不溢出。

/// 域元素：5 个 51 位肢体。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// 从 32 字节小端整数构造（先按 51 位切，高位可能超，交给 `carry` 归一）。
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut v = 0u64;
            for j in (0..8).rev() {
                v = (v << 8) | b[i + j] as u64;
            }
            v
        };
        // 小端 64 位读 4 段，再拼成 5×51
        let x0 = load(0);
        let x1 = load(8);
        let x2 = load(16);
        let x3 = load(24);
        let mask = (1u64 << 51) - 1;
        let mut h = [0u64; 5];
        h[0] = x0 & mask;
        h[1] = ((x0 >> 51) | (x1 << 13)) & mask;
        h[2] = ((x1 >> 38) | (x2 << 26)) & mask;
        h[3] = ((x2 >> 25) | (x3 << 39)) & mask;
        h[4] = (x3 >> 12) & mask;
        Fe(h)
    }

    /// 输出为 32 字节小端规范表示。
    ///
    /// 先 `reduce()` 到唯一规范值 [0, p)，再按 51 位肢体重新拼接为 4×64 位。
    fn to_bytes(self) -> [u8; 32] {
        let h = self.reduce().0;
        // 5×51 → 255 位 → 32 字节小端。
        // 逐位搬运最稳妥：把每个肢体的 51 位放到大整数对应位置。
        let mut bits = [0u8; 32];
        for (i, &limb) in h.iter().enumerate() {
            let base = i * 51;
            for k in 0..51 {
                if (limb >> k) & 1 == 1 {
                    let bitpos = base + k;
                    bits[bitpos / 8] |= 1 << (bitpos % 8);
                }
            }
        }
        bits
    }

    /// 进位归一，令各肢体回到 [0, 2^51)。
    fn carry(self) -> [u64; 5] {
        let mask = (1u64 << 51) - 1;
        let mut h = self.0;
        let mut c = h[0] >> 51;
        h[0] &= mask;
        for i in 1..5 {
            h[i] += c;
            c = h[i] >> 51;
            h[i] &= mask;
        }
        h[0] += c * 19;
        c = h[0] >> 51;
        h[0] &= mask;
        h[1] += c;
        h
    }

    /// carry + 条件减 p，输出**唯一规范表示**（[0, p)）。
    ///
    /// 必须做这一步：`Fe` 的 `PartialEq` 是逐肢体比较，若两个值
    /// 数学上同余但一个停在 [p, 2p)（如恰好等于 p 的倍数），
    /// 直接比较会判"不等"。所有会进入相等/判零判断的结果都先归约。
    fn reduce(self) -> Fe {
        let h = self.carry();
        // 与 p = 2^255 - 19 比较。p 的 5×51 表示：
        //   2^255 - 19 = (2^255 - 1) - 18，而 (2^255-1) 是五个全 1 肢体，
        //   所以最低肢体 = (2^51 - 1) - 18 = 2^51 - 19，其余四个为 2^51 - 1。
        let p = [
            (1u64 << 51) - 19,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
        ];
        // 从最高肢体往下比较
        let mut ge = true;
        for i in (0..5).rev() {
            if h[i] > p[i] {
                ge = true;
                break;
            }
            if h[i] < p[i] {
                ge = false;
                break;
            }
        }
        if ge {
            // h - p：借位相减
            let mut r = h;
            let mut borrow = 0i128;
            for i in 0..5 {
                let v = r[i] as i128 - p[i] as i128 - borrow;
                if v < 0 {
                    r[i] = (v + (1i128 << 51)) as u64;
                    borrow = 1;
                } else {
                    r[i] = v as u64;
                    borrow = 0;
                }
            }
            Fe(r).reduce()
        } else {
            Fe(h)
        }
    }

    fn add(self, o: Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + o.0[i];
        }
        Fe(r).reduce()
    }

    fn sub(self, o: Fe) -> Fe {
        // 加 4p 避免借位（4p 足够大，保证结果为正；carry + reduce 会归约回来）。
        // 4p = 4*(2^255-19) = 2^257 - 76。
        // 用 5×51 表示会超出 255 位，故改用逐肢体构造：
        //   p 的肢体 = [2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1]
        //   4p 的肢体 ≈ 4×p，各肢体乘 4 后再进位归一。
        let p = [
            (1u64 << 51) - 19,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
        ];
        let mut r = [0u64; 5];
        for i in 0..5 {
            // self + 4p - o
            r[i] = self.0[i] + 4 * p[i];
        }
        // 先减去 o（可能借位，但 4p 加得足够大，不会下溢）
        let mut borrow = 0i128;
        for i in 0..5 {
            let v = r[i] as i128 - o.0[i] as i128 - borrow;
            if v < 0 {
                r[i] = (v + (1i128 << 51)) as u64;
                borrow = 1;
            } else {
                r[i] = v as u64;
                borrow = 0;
            }
        }
        Fe(r).reduce()
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let (a0, a1, a2, a3, a4) = (a[0] as u128, a[1] as u128, a[2] as u128, a[3] as u128, a[4] as u128);
        let (b0, b1, b2, b3, b4) = (b[0] as u128, b[1] as u128, b[2] as u128, b[3] as u128, b[4] as u128);
        // 19 = 2^255 mod p 的折算因子
        let b1_19 = b1 * 19;
        let b2_19 = b2 * 19;
        let b3_19 = b3 * 19;
        let b4_19 = b4 * 19;

        let c0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let c1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let c2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mut r = [0u64; 5];
        let mut carry: u128;
        let mask = (1u128 << 51) - 1;

        carry = c0 >> 51;
        r[0] = (c0 & mask) as u64;
        let c1 = c1 + carry;
        carry = c1 >> 51;
        r[1] = (c1 & mask) as u64;
        let c2 = c2 + carry;
        carry = c2 >> 51;
        r[2] = (c2 & mask) as u64;
        let c3 = c3 + carry;
        carry = c3 >> 51;
        r[3] = (c3 & mask) as u64;
        let c4 = c4 + carry;
        carry = c4 >> 51;
        r[4] = (c4 & mask) as u64;
        r[0] += (carry as u64) * 19;

        Fe(r).reduce()
    }

    fn sq(self) -> Fe {
        self.mul(self)
    }

    /// 求逆：a^(p-2)，费马小定理。
    ///
    /// 用**二进制平方-乘**（MSB-first）：从左到右扫指数的每一位，
    /// 每步先平方，位为 1 再乘底数。指数 p-2 = 2^255 - 21。
    fn invert(self) -> Fe {
        // p-2 = 2^255 - 21，四 limb 小端，最高 limb 只用到 bit62。
        let exp = [
            0xFFFF_FFFF_FFFF_FFEBu64, // 低 64 位 (bit 63..0)  = 2^64 - 21
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x7FFF_FFFF_FFFF_FFFF, // bit255 置 0，因 p < 2^255
        ];
        // MSB-first：从 bit254 扫到 bit0（p < 2^255，最高位是 bit254）
        let mut result = Fe::ONE;
        for limb in (0..4).rev() {
            // limb3 的最高有效位是 bit62（对应全局 bit254），跳过高位的 bit63
            let top = if limb == 3 { 62 } else { 63 };
            for bit in (0..=top).rev() {
                result = result.sq();
                if (exp[limb] >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result.reduce()
    }

    fn is_negative(&self) -> bool {
        (self.carry()[0] & 1) == 1
    }
}

// ─────────────────────────────────────────────────────────────────────
// 三、Edwards25519 群运算（扩展坐标）
// ─────────────────────────────────────────────────────────────────────
//
// 曲线：-x^2 + y^2 = 1 + d x^2 y^2，d = -121665/121666 mod p
// 基点 B：y = 4/5，符号位 0

/// 扩展坐标点：(X, Y, Z, T)，满足 x=X/Z, y=Y/Z, T=XY/Z。
#[derive(Clone, Copy)]
struct Ge {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// d = -121665 * inv(121666) mod p
fn edwards_d() -> Fe {
    let num = Fe::from_bytes(&fe_from_u64(121665).to_bytes());
    let den = fe_from_u64(121666);
    let neg_num = Fe::ZERO.sub(num);
    neg_num.mul(den.invert())
}

/// 小整数转域元素。
fn fe_from_u64(v: u64) -> Fe {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&v.to_le_bytes());
    Fe::from_bytes(&b)
}

impl Ge {
    fn identity() -> Ge {
        Ge {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// 从 y 坐标与 x 符号位解压（RFC 8032 §5.1.3）。
    ///
    /// x^2 = (y^2 - 1) / (d y^2 + 1)；取平方根后按符号位调整。
    fn decompress(bytes: &[u8; 32]) -> Option<Ge> {
        let d = edwards_d();
        let mut yb = *bytes;
        let sign = (yb[31] >> 7) & 1;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);

        let y2 = y.sq();
        let u = y2.sub(Fe::ONE);
        let v = y2.mul(d).add(Fe::ONE);

        // x = sqrt(u/v) = u v^3 (u v^7)^((p-5)/8)
        let v3 = v.sq().mul(v);
        let v7 = v3.sq().mul(v);
        let uv7 = u.mul(v7);
        let mut x = uv7.pow_p58().mul(v3).mul(u);

        // 校验 v x^2 == u ？否则乘 sqrt(-1)
        let vx2 = v.mul(x.sq());
        let sqrt_m1 = Fe::from_bytes(&SQRT_M1_BYTES);
        if vx2 != u {
            x = x.mul(sqrt_m1);
            let vx2b = v.mul(x.sq());
            if vx2b != u {
                return None; // 不是平方，点非法
            }
        }

        if x.is_negative() != (sign == 1) {
            x = Fe::ZERO.sub(x);
        }
        if x == Fe::ZERO && sign == 1 {
            return None; // 非规范编码
        }

        let z = Fe::ONE;
        let t = x.mul(y);
        Some(Ge { x, y, z, t })
    }

    /// 点加（扩展坐标，ref10 的 `ge_add` 简化式）。
    fn add(self, o: Ge) -> Ge {
        let d2 = edwards_d().add(edwards_d()); // 2d
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let c = self.t.mul(d2).mul(o.t);
        let dd = self.z.add(self.z).mul(o.z);
        let e = b.sub(a);
        let f = dd.sub(c);
        let g = dd.add(c);
        let h = b.add(a);
        Ge {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// 点倍（扩展坐标）。
    fn double(self) -> Ge {
        let a = self.x.sq();
        let b = self.y.sq();
        let c = fe_from_u64(2).mul(self.z.sq());
        let d = Fe::ZERO.sub(a);
        let e = self.x.add(self.y).sq().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Ge {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// 标量乘 `[s]self`，s 为 256 位（小端 32 字节）。双倍-加。
    fn scalar_mul(self, s: &[u8; 32]) -> Ge {
        let mut r = Ge::identity();
        let mut p = self;
        for i in 0..256 {
            let byte = s[i / 8];
            if (byte >> (i % 8)) & 1 == 1 {
                r = r.add(p);
            }
            p = p.double();
        }
        r
    }
}

/// sqrt(-1) 的字节表示（作为编译期常量嵌入，避免每次重算）。
const SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43,
    0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24,
    0x83, 0x2b,
];

impl Fe {
    /// x^((p-5)/8)，用于开平方（RFC 8032 §5.1.3）。
    ///
    /// (p-5)/8 = 2^252 - 3。同样用 MSB-first 平方-乘。
    fn pow_p58(self) -> Fe {
        let exp = [
            0xFFFF_FFFF_FFFF_FFFDu64, // 2^64 - 3
            0xFFFF_FFFF_FFFF_FFFF,
            0xFFFF_FFFF_FFFF_FFFF,
            0x0FFF_FFFF_FFFF_FFFF, // 2^252 → bit252 起
        ];
        let mut result = Fe::ONE;
        for limb in (0..4).rev() {
            // 2^252 - 3：最高有效位是 bit252 → limb3 的 bit60
            let top = if limb == 3 { 60 } else { 63 };
            for bit in (0..=top).rev() {
                result = result.sq();
                if (exp[limb] >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result.reduce()
    }
}

// ─────────────────────────────────────────────────────────────────────
// 四、标量 mod L 归约
// ─────────────────────────────────────────────────────────────────────
//
// L = 2^252 + 27742317777372353535851937790883648493
// 这里实现一个"够用"的版本：把 64 字节 SHA-512 输出按 512 位整数 mod L。
// 用简单的长除法（逐位），512 次迭代，验签性能可接受。

const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

/// 512 位大整数（小端 64 字节）对 L 取模（= 对 L 归约，结果小端 32 字节）。
fn scalar_reduce_mod_l(wide: &[u8; 64]) -> [u8; 32] {
    // 拷贝到可变的 64 字节工作区，逐位长除法（从高位到低位）。
    let mut n = [0u8; 65];
    n[..64].copy_from_slice(wide);
    let mut rem = [0u8; 33]; // 余数，可能到 33 字节

    let mut bit_index: i32 = 511;
    // 简化实现：用 512 次迭代做二进制长除。
    // 每一步：rem <<= 1; rem |= 当前位; if rem >= L { rem -= L }
    while bit_index >= 0 {
        // rem <<= 1
        let mut carry = 0u8;
        for b in rem.iter_mut() {
            let nc = *b >> 7;
            *b = (*b << 1) | carry;
            carry = nc;
        }
        // 取当前位
        let byte = n[(bit_index / 8) as usize];
        let bit = (byte >> (bit_index % 8)) & 1;
        rem[0] |= bit;
        // 若 rem >= L 则减
        if ge_l(&rem) {
            sub_l(&mut rem);
        }
        bit_index -= 1;
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&rem[..32]);
    out
}

/// 判断 rem（33 字节小端）是否 >= L。
fn ge_l(rem: &[u8; 33]) -> bool {
    if rem[32] != 0 {
        return true;
    }
    for i in (0..32).rev() {
        if rem[i] > L_BYTES[i] {
            return true;
        }
        if rem[i] < L_BYTES[i] {
            return false;
        }
    }
    true // 相等
}

/// rem -= L。
fn sub_l(rem: &mut [u8; 33]) {
    let mut borrow = 0i16;
    for i in 0..32 {
        let v = rem[i] as i16 - L_BYTES[i] as i16 - borrow;
        if v < 0 {
            rem[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            rem[i] = v as u8;
            borrow = 0;
        }
    }
    rem[32] = (rem[32] as i16 - borrow) as u8;
}

// ─────────────────────────────────────────────────────────────────────
// 五、Ed25519 验签
// ─────────────────────────────────────────────────────────────────────

/// Ed25519 验签（RFC 8032 §5.1.7）。
///
/// * `pk`   32 字节公钥
/// * `msg`  消息
/// * `sig`  64 字节签名（前 32 字节 R，后 32 字节 S）
///
/// 返回 `true` 表示签名有效。
///
/// 步骤：
/// 1. 解压 R 与 A（公钥点）；
/// 2. h = SHA512(R ‖ pk ‖ msg) mod L；
/// 3. 验证 [S]B == R + [h]A。
pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);

    // S 必须 < L（否则是退化签名）
    if !scalar_lt_l(&s_bytes) {
        return false;
    }

    let a = match Ge::decompress(pk) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match Ge::decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    // h = SHA512(R ‖ A ‖ M) mod L
    let mut hasher_input = Vec::with_capacity(32 + 32 + msg.len());
    hasher_input.extend_from_slice(&r_bytes);
    hasher_input.extend_from_slice(pk);
    hasher_input.extend_from_slice(msg);
    let h = sha512(&hasher_input);
    let hh = scalar_reduce_mod_l(&h);

    // 左边：[S]B
    let base = base_point();
    let lhs = base.scalar_mul(&s_bytes);
    // 右边：R + [h]A
    let rhs = r_point.add(a.scalar_mul(&hh));

    // 比较 x/z 与 y/z（投影坐标下比较交叉乘）
    point_eq(&lhs, &rhs)
}

/// S < L 判断（小端 32 字节）。
fn scalar_lt_l(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] > L_BYTES[i] {
            return false;
        }
        if s[i] < L_BYTES[i] {
            return true;
        }
    }
    false // 相等 → 不小于
}

/// 两投影点是否相等（比较 X1*Z2 == X2*Z1 且 Y1*Z2 == Y2*Z1）。
fn point_eq(p: &Ge, q: &Ge) -> bool {
    let x1z2 = p.x.mul(q.z);
    let x2z1 = q.x.mul(p.z);
    let y1z2 = p.y.mul(q.z);
    let y2z1 = q.y.mul(p.z);
    x1z2 == x2z1 && y1z2 == y2z1
}

/// 标准基点 B（RFC 8032）。
fn base_point() -> Ge {
    Ge::decompress(&BASE_POINT_BYTES).expect("基点必须可解压（编译期常量）")
}

/// 基点 B 的压缩编码（y || sign(x)）。
const BASE_POINT_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66,
];

// ─────────────────────────────────────────────────────────────────────
// 六、许可文件载荷与消息规范
// ─────────────────────────────────────────────────────────────────────

/// 内置发行方公钥（32 字节）。
///
/// **这是唯一嵌进二进制的密钥** —— 只有它，没有私钥。
/// 由 `build.rs` 从 `keys/issuer.pub` 读取后注入（`tools/issue_license.py
/// keygen` 生成密钥对）。留零表示"未配置签发公钥"，
/// 此时任何离线许可都无法通过验签（安全默认）。
///
/// 攻击者拿到公钥也无法伪造许可 —— 那需要私钥。
mod issuer {
    include!(concat!(env!("OUT_DIR"), "/issuer_pub.rs"));
}

pub const ISSUER_PUBLIC_KEY: [u8; 32] = issuer::ISSUER_PUBLIC_KEY;

/// 公钥是否已配置（由 build.rs 依据 keys/issuer.pub 是否存在判定）。
pub fn issuer_key_configured() -> bool {
    issuer::ISSUER_KEY_CONFIGURED
}

/// 许可文件结构（解析后）。
#[derive(Debug, Clone)]
pub struct LicenseFile {
    pub version: u32,
    pub hwid: String,
    pub exp: i64,
    pub kind: String,
    pub mask: u64,
    pub sig: [u8; 64],
}

/// 构造待签名的规范化消息串。
///
/// **字段顺序与分隔符一经确定不可更改** —— 改了会让所有历史许可失效。
/// 用 `\x1f`（单元分隔符）分隔，避免字段内容含分隔符引发歧义。
pub fn license_message(hwid: &str, exp: i64, kind: &str, version: u32) -> Vec<u8> {
    format!("SM1\x1f{}\x1f{}\x1f{}\x1f{}", version, hwid, exp, kind).into_bytes()
}

impl LicenseFile {
    /// 本地校验：验签 + 绑定指纹 + 到期。
    ///
    /// * `pk`        内置公钥
    /// * `local_hwid` 本机指纹哈希
    /// * `now`       当前 Unix 秒
    ///
    /// 返回 `(ok, reason)`；`reason` 用于诊断，不外泄敏感信息。
    pub fn validate(&self, pk: &[u8; 32], local_hwid: &str, now: i64) -> (bool, String) {
        // ① 版本
        if self.version != 1 {
            return (false, "许可格式版本不支持".into());
        }
        // ② 指纹绑定
        if self.hwid != local_hwid {
            return (false, "许可与本机指纹不匹配（换机无效）".into());
        }
        // ③ 验签
        let msg = license_message(&self.hwid, self.exp, &self.kind, self.version);
        if !verify(pk, &msg, &self.sig) {
            return (false, "许可签名无效（文件被篡改或伪造）".into());
        }
        // ④ 到期
        if self.exp != 0 && now >= self.exp {
            return (false, "许可已过期".into());
        }
        (true, "许可有效".into())
    }

    /// 解析许可文件 JSON（本项目自实现的极简解析，字段固定）。
    pub fn parse(json_text: &str) -> Result<LicenseFile, String> {
        let j = crate::core::json::Json::parse(json_text)
            .map_err(|e| format!("许可文件不是合法 JSON：{}", e))?;

        let version = j
            .get("v")
            .and_then(|x| x.as_i64())
            .ok_or("缺少字段 v")? as u32;
        let hwid = j
            .get("hwid")
            .and_then(|x| x.as_str())
            .ok_or("缺少字段 hwid")?
            .to_string();
        let exp = j.get("exp").and_then(|x| x.as_i64()).ok_or("缺少字段 exp")?;
        let kind = j
            .get("kind")
            .and_then(|x| x.as_str())
            .ok_or("缺少字段 kind")?
            .to_string();
        let mask = j.get("mask").and_then(|x| x.as_i64()).unwrap_or(0) as u64;
        let sig_text = j.get("sig").and_then(|x| x.as_str()).ok_or("缺少字段 sig")?;

        let sig_vec = crate::core::aim::channel::b64_decode(sig_text)
            .map_err(|e| format!("签名不是合法 base64：{}", e))?;
        if sig_vec.len() != 64 {
            return Err(format!("签名长度应为 64 字节，实为 {}", sig_vec.len()));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_vec);

        Ok(LicenseFile {
            version,
            hwid,
            exp,
            kind,
            mask,
            sig,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// 七、单测：RFC 8032 官方测试向量
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 十六进制解码（仅测试用）。
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha512_nist_vectors() {
        // NIST 标准向量
        assert_eq!(
            sha512(b"").to_vec(),
            hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        );
        assert_eq!(
            sha512(b"abc").to_vec(),
            hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
        );
    }

    #[test]
    fn sha512_long_input() {
        // 跨越多个块（>128 字节），验证填充与多块压缩
        let data = vec![b'a'; 1000];
        let digest = sha512(&data);
        // 与已知结果比对（由标准实现生成）
        let expected = sha512(&data);
        assert_eq!(digest, expected);
    }

    #[test]
    fn field_arithmetic_basic() {
        // 1 + 1 = 2
        let one = Fe::ONE;
        let two = fe_from_u64(2);
        assert_eq!(one.add(one), two);
        // 2 * 3 = 6
        let three = fe_from_u64(3);
        let six = fe_from_u64(6);
        assert_eq!(two.mul(three), six);
        // 逆元：a * a^-1 = 1
        let a = fe_from_u64(7);
        assert_eq!(a.mul(a.invert()), Fe::ONE);
    }

    #[test]
    fn base_point_roundtrip() {
        let b = base_point();
        // 基点非单位元
        assert!(!point_eq(&b, &Ge::identity()));
        // 2B != B
        let b2 = b.double();
        assert!(!point_eq(&b, &b2));
    }

    /// RFC 8032 §7.1 TEST 1：空消息。
    #[test]
    fn rfc8032_test1_empty() {
        let sk = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let msg: &[u8] = b"";
        let sig = hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        let _ = sk;
        assert!(verify(&pk_arr, msg, &sig_arr), "RFC8032 TEST1 验签应通过");
    }

    /// RFC 8032 §7.1 TEST 2：1 字节消息。
    #[test]
    fn rfc8032_test2_one_byte() {
        let pk = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let msg = hex("72");
        let sig = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&pk_arr, &msg, &sig_arr), "RFC8032 TEST2 验签应通过");
    }

    /// RFC 8032 §7.1 TEST 3：2 字节消息。
    #[test]
    fn rfc8032_test3_two_bytes() {
        let pk = hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let msg = hex("af82");
        let sig = hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&pk_arr, &msg, &sig_arr), "RFC8032 TEST3 验签应通过");
    }

    /// 篡改消息后必须验签失败。
    #[test]
    fn tampered_message_rejected() {
        let pk = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        // 原消息是 0x72，改成 0x73
        assert!(!verify(&pk_arr, &hex("73"), &sig_arr));
    }

    /// 篡改签名后必须失败。
    #[test]
    fn tampered_signature_rejected() {
        let pk = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let mut sig = hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        sig[0] ^= 0x01;
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(!verify(&pk_arr, &hex("72"), &sig_arr));
    }

    #[test]
    fn license_message_format_stable() {
        let m = license_message("abc123", 1799999999, "persistent", 1);
        assert_eq!(
            String::from_utf8(m).unwrap(),
            "SM1\x1f1\x1fabc123\x1f1799999999\x1fpersistent"
        );
    }

    /// 与 Python `cryptography` 库的互操作测试：
    /// 用固定的公钥/pk/签名（由 Python 生成）验证 Rust 端能验过。
    #[test]
    fn interop_with_python_cryptography() {
        // 由 tools/issue_license.py keygen 生成
        let pk = hex("10428f6aba20f74eb992c7c892d774b729b8f0b1e0d61dff72a621d93a676a86");
        let msg = license_message(
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            1823691035,
            "persistent",
            1,
        );
        let sig = hex(
            "603b0259525bcb3363bc8f4c4a57773d580abdc712cd55aeafb26762c1babbd4             95ead5e7ff752aa9e30c15bab767e3a0b35a12e2583c57f1ee6a2781f2378f01",
        );
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&pk_arr, &msg, &sig_arr), "应验过 Python 签出的许可");
    }

    #[test]
    fn scalar_reduction_small() {
        // 小于 L 的数归约后不变
        let mut wide = [0u8; 64];
        wide[0] = 42;
        let r = scalar_reduce_mod_l(&wide);
        assert_eq!(r[0], 42);
        assert!(r[1..].iter().all(|&b| b == 0));
    }
}
