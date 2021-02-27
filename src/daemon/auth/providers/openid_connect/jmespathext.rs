use std::sync::Arc;

use jmespatch as jmespath;
use jmespath::functions::{ArgumentType, CustomFunction, Signature};
use jmespath::{Context, Rcvar, Runtime};

use regex::Regex;

/// Create a customized instance of the JMESPath runtime with support for the
/// standard functions and two additional custom functions: recap and resub.
pub fn init_runtime() -> Runtime {
    let mut runtime = Runtime::new();

    runtime.register_builtin_functions();
    runtime.register_function("recap", make_recap_fn());
    runtime.register_function("resub", make_resub_fn());

    runtime
}

/// Custom JMESPath recap(haystack, regex) function that returns the value of
/// the first capture group of the first match in the haystack by the specified
/// regex.
///
/// Returns an empty string if no match is found.
fn make_recap_fn() -> Box<CustomFunction> {
    let fn_signature = Signature::new(vec![ArgumentType::String, ArgumentType::String], None);

    let fn_impl = Box::new(|args: &[Rcvar], _: &mut Context| {
        trace!("jmespath recap() arguments: {:?}", args);

        let mut res = String::new();

        if let jmespath::Variable::String(str) = &*args[0] {
            if let jmespath::Variable::String(re_str) = &*args[1] {
                let re = Regex::new(&re_str).expect(&format!("Invalid regular expression for '{}' for recap() JMESPath function", &re_str));
                let caps = re.captures_iter(&str).next().unwrap();
                res = caps[1].to_string();
            }
        }

        trace!("jmespath recap() result: {}", &res);
        Ok(Arc::new(jmespath::Variable::String(res)))
    });

    Box::new(CustomFunction::new(fn_signature, fn_impl))
}

/// Custom JMESPath resub(haystack, needle regex, replacement value) function
/// that returns the result of replacing the first text in the haystack that
/// matches the needle regex with the given replacement value.
///
/// Returns the given string unchanged if no match is found to replace.
fn make_resub_fn() -> Box<CustomFunction> {
    let fn_signature = Signature::new(
        vec![ArgumentType::String, ArgumentType::String, ArgumentType::String],
        None,
    );

    let fn_impl = Box::new(|args: &[Rcvar], _: &mut Context| {
        trace!("jmespath fn resub() arguments: {:?}", args);

        let mut res = String::new();

        if let jmespath::Variable::String(str) = &*args[0] {
            if let jmespath::Variable::String(re_str) = &*args[1] {
                if let jmespath::Variable::String(newval) = &*args[2] {
                    let re = Regex::new(&re_str).expect(&format!("Invalid regular expression for '{}' for resub() JMESPath function", &re_str));
                    res = re.replace(str.as_str(), newval.as_str()).to_string();
                }
            }
        }

        trace!("jmespath resub() result: {}", &res);
        Ok(Arc::new(jmespath::Variable::String(res)))
    });

    Box::new(CustomFunction::new(fn_signature, fn_impl))
}
