use std::collections::HashMap;
use vivutils::function::Function;

pub fn get_function_meta(function: Function) -> HashMap<String, i32> {
    let meta: HashMap<String, i32> = function
        .workspace
        .get_function_meta_dict(function.virtual_address);
    let mut map = HashMap::new();
    map.insert(
        "size".to_string(),
        meta.get(&"Size".to_string()).unwrap().clone(),
    );
    map.insert(
        "block_count".to_string(),
        meta.get(&"BlockCount".to_string()).unwrap().clone(),
    );
    map.insert(
        "instruction_count".to_string(),
        meta.get(&"InstructionCount".to_string()).unwrap().clone(),
    );
    map.insert("score".to_string(), 0);

    map.clone()
}
