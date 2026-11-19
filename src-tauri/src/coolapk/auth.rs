use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bcrypt::{BASE_64 as BCRYPT_BASE64, Version, hash_with_salt};
use md5::{Digest, Md5};
use std::time::{SystemTime, UNIX_EPOCH};

const APP_ID: &str = "com.coolapk.market";
const APP_CODE: u64 = 2_611_121;
const AUTH_BLOB_B64: &str = include_str!("auth_blob.b64");

/// 酷安 Token V3 离线签名器。
///
/// 算法与项目 Python SDK 保持一致：按时间选取密码表片段，组合设备摘要，
/// 再通过 bcrypt 生成酷安 API 接受的 v3 token。
pub struct CoolapkAuth {
    device_code: String,
    auth_blob: Vec<u8>,
}

impl CoolapkAuth {
    pub fn new(device_code: impl Into<String>) -> Self {
        let auth_blob = BASE64
            .decode(AUTH_BLOB_B64.trim())
            .expect("embedded Coolapk auth blob must be valid base64");

        Self {
            device_code: device_code.into(),
            auth_blob,
        }
    }

    /// 运行时切换设备码（登录/切换账号/游客态之间切换时调用）。
    /// Token V3 与设备码绑定，切换后所有后续请求的签名使用新设备码。
    pub fn set_device_code(&mut self, device_code: String) {
        self.device_code = device_code;
    }

    pub fn get_app_token(&self) -> Result<String, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();

        // 某些时间点生成的 22 位盐不满足 bcrypt 字符表，和 Python SDK 一样
        // 最多向前探测 15 秒寻找下一组有效盐。
        let mut last_error = String::new();
        for offset in 0..=15 {
            match self.generate_token_at(timestamp + offset) {
                Ok(token) => return Ok(token),
                Err(error) => last_error = error,
            }
        }

        Err(format!("failed to generate Coolapk token: {last_error}"))
    }

    fn generate_token_at(&self, timestamp: u64) -> Result<String, String> {
        let index = (((timestamp + APP_CODE) % 100) * 4 + 0x80) as usize;
        let chunk = self
            .auth_blob
            .get(index..index + 0x80)
            .ok_or_else(|| "auth blob lookup exceeded its bounds".to_string())?;
        let segment = BASE64
            .decode(chunk)
            .map_err(|e| format!("invalid auth blob segment: {e}"))?;

        let device_md5 = md5_hex(self.device_code.as_bytes());
        let plain = format!(
            "{}&{}&{}&{}&{}",
            APP_ID,
            String::from_utf8_lossy(&segment),
            device_md5,
            timestamp,
            APP_CODE
        );

        let password = md5_hex(BASE64.encode(plain.as_bytes()).as_bytes());
        let salt_source = BASE64
            .encode(format!("{:x}/{}", timestamp, md5_hex(plain.as_bytes())))
            .trim_end_matches('=')
            .to_string();
        // 官方实现的盐 = 标准 base64 前 21 位 + 固定 '.'；末位不是 base64 字符，
        // 但 bcrypt 只取它的高 2 位，实测与官方 token 逐字节一致。
        let salt22 = format!(
            "{}.",
            salt_source
                .get(..21)
                .ok_or_else(|| "generated salt is too short".to_string())?
        );

        let salt_bytes = BCRYPT_BASE64
            .decode(salt22.as_bytes())
            .map_err(|e| format!("invalid bcrypt salt: {e}"))?;
        let salt: [u8; 16] = salt_bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| format!("invalid bcrypt salt length: {}", bytes.len()))?;
        // 酷安当前 Token V3 校验使用 bcrypt cost=4；cost=10 会导致登录校验返回“登录信息有误”。
        let hash = hash_with_salt(password.as_bytes(), 4, salt)
            .map_err(|e| format!("bcrypt failed: {e}"))?
            .format_for_version(Version::TwoY);

        Ok(format!(
            "v3{}",
            BASE64.encode(hash.as_bytes()).trim_end_matches('=')
        ))
    }
}

fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod probe_tests {
    use super::CoolapkAuth;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    #[test]
    fn probe_salt_for_known_real_timestamp() {
        let device = "gNykjY3ITZjRzNlRTY0gzNgsTMwAjLyETOwQjMuE0MRFEI7MkMxITM4AjMyAyOp1GZlJFI7kWbvFWaYByOgsDI7AyOmdWQFZFOLRFZKVjSIBnU1AXQXJjN5YzTlBlSt0CM1gUd3UFR";
        let auth = CoolapkAuth::new(device);
        let token = auth.generate_token_at(1_795_096_595).unwrap();
        let body = &token[2..];
        let padded = format!("{body}{}", "=".repeat((4 - body.len() % 4) % 4));
        let decoded = String::from_utf8(BASE64.decode(padded).unwrap()).unwrap();
        println!("PROBE_SALT={decoded}");
        println!("REAL_SALT=$2y$04$NmFmZWYwMTMvZGVmZTQwZ.Q/letpnjTvhRLkevU06/rbD/hFq4UEi");
    }
}

#[cfg(test)]
mod tests {
    use super::CoolapkAuth;

    #[test]
    fn token_is_deterministic_for_a_synthetic_device_and_timestamp() {
        let auth = CoolapkAuth::new("synthetic-test-device");
        let first = auth.generate_token_at(1_770_000_000).unwrap();
        let second = auth.generate_token_at(1_770_000_000).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("v3"));
        assert!(first.len() > 70);
    }
}
