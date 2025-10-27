use chrono::Utc;

fn main() {
    // Genera el timestamp de build
    let build_time = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Establece la variable de entorno para que esté disponible en tiempo de compilación
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);

    // Configura cfg flags personalizados
    println!("cargo:rustc-check-cfg=cfg(disabled_test)");

    // Re-ejecutar si cambia este script
    println!("cargo:rerun-if-changed=build.rs");
}
