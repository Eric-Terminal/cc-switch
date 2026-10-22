#[test]
fn bundled_roots_exclude_distrusted_emsign_g3() {
    // 代理直连和 CONNECT 路径都从这个兼容包加载根证书；检查实际信任集合，
    // 防止只升级 0.26 包名、却仍解析到含失信根的旧 1.x 数据库。
    let distrusted_subject = b"emSign ECC Root CA - G3";
    assert!(!webpki_roots::TLS_SERVER_ROOTS.iter().any(|anchor| {
        anchor
            .subject
            .as_ref()
            .windows(distrusted_subject.len())
            .any(|part| part == distrusted_subject)
    }));
    assert!(
        webpki_roots::TLS_SERVER_ROOTS.len() > 100,
        "不能通过清空信任库来移除失信根"
    );
}
