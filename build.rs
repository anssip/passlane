fn main() {
    cynic_codegen::register_schema("passlane")
        .from_sdl_file("src/schema.graphql")
        .unwrap()
        .as_default()
        .unwrap();
}
