package com.fuxi.ghostroot;

/**
 * Shell 通道抽象。
 *
 * GhostRoot 拿 shell 域有两条路：
 *   1) 0073（Adb0073 的 TLS socket）        —— 主路，走漏洞
 *   2) Shizuku（借 Shizuku 服务的 shell 域）—— 兜底，走"正路"
 *
 * 拿域之后的所有操作（推 8550 / 找 ksud / 跑提权）都与通道无关，
 * 统一走这个接口，于是两条路可以无缝切换。
 */
public interface Shell {

    /** 通道名字，用于日志。 */
    String name();

    /** 在 shell 域执行命令，返回 stdout+stderr 合并文本；失败返回 null。 */
    String exec(String cmd);

    /** 通道自带的日志（例如 0073 的握手过程）；没有则返回空串。 */
    String log();

    /** 把一段字节数据写到远端路径，成功返回 true。 */
    boolean push(byte[] data, String remote);

    /** 断言这个通道真的在 shell 域（uid=2000 或 0）。 */
    boolean verify();

    /** 关闭/清理。 */
    void close();
}