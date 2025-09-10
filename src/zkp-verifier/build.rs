fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    if !target.contains("windows") {
        cxx_build::bridge("src/lib.rs")
            .file("src/cpp_integration.cpp")
            .flag_if_supported("-std=c++14")
            .compile("zkp-verifier");
        println!("cargo:rerun-if-changed=src/cpp_integration.cpp");
    }
    
    println!("cargo:rerun-if-changed=src/lib.rs");
}