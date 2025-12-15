#include <jni.h>
#include <string>

#include "u2t_tlcp_android.h"


extern "C" {
JNIEXPORT jstring JNICALL
Java_com_wireguard_android_backend_GoBackend_run(JNIEnv *env, jclass clazz, jstring tcp_addr,
                                    jstring udp_addr, jstring chain_ca_cert, jstring log_level, jstring virtual_network) {
    // 将Java字符串转换为C字符串
    const char *tcp_cstr = env->GetStringUTFChars(tcp_addr, nullptr);
    const char *udp_cstr = env->GetStringUTFChars(udp_addr, nullptr);
    const char *chain_ca_cert_cstr = env->GetStringUTFChars(chain_ca_cert, nullptr);
    const char *log_level_cstr = env->GetStringUTFChars(log_level, nullptr);
    const char *virtual_network_cstr = env->GetStringUTFChars(virtual_network, nullptr);

    // 构造COptions结构体
    COptions c_opts = {
            .tcp_addr = tcp_cstr,
            .udp_addr = udp_cstr,
            .chain_ca_cert = chain_ca_cert_cstr,
            .log_level = log_level_cstr,
            .virtual_network = virtual_network_cstr
    };

    // 调用Rust的run函数
    char *result = run(&c_opts);

    // 释放Java字符串转换的C字符串
    env->ReleaseStringUTFChars(tcp_addr, tcp_cstr);
    env->ReleaseStringUTFChars(udp_addr, udp_cstr);
    env->ReleaseStringUTFChars(chain_ca_cert, chain_ca_cert_cstr);
    env->ReleaseStringUTFChars(log_level, log_level_cstr);
    env->ReleaseStringUTFChars(virtual_network, virtual_network_cstr);

    if (!result) {
        return env->NewStringUTF("");
    }
    jstring jstr = env->NewStringUTF(result);
    free_c_string(result);  // 立即释放Rust返回的字符串
    return jstr;
}
}
