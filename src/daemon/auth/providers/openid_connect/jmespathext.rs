use std::sync::Arc;

use jmespatch as jmespath;
use jmespath::functions::{ArgumentType, CustomFunction, Signature};
use jmespath::{Context, ErrorReason, JmespathError, Rcvar, Runtime};

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
    let fn_signature = Signature::new(vec![ArgumentType::Any, ArgumentType::String], None);

    let fn_impl = Box::new(|args: &[Rcvar], _: &mut Context| {
        trace!("jmespath recap() arguments: {:?}", args);

        let mut res = String::new();

        if let jmespath::Variable::String(str) = &*args[0] {
            if let jmespath::Variable::String(re_str) = &*args[1] {
                match Regex::new(re_str) {
                    Ok(re) => {
                        let mut iter = re.captures_iter(str);
                        if let Some(captures) = iter.next() {
                            // captures[0] is the entire match
                            // captures[1] is the value of the first capture group match
                            res = captures[1].to_string();
                        }
                    }
                    Err(err) => {
                        return Err(JmespathError::new(
                            re_str,
                            0,
                            ErrorReason::Parse(format!("Invalid regular expression: {}", err)),
                        ));
                    }
                }
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
        vec![ArgumentType::Any, ArgumentType::String, ArgumentType::String],
        None,
    );

    let fn_impl = Box::new(|args: &[Rcvar], _: &mut Context| {
        trace!("jmespath fn resub() arguments: {:?}", args);

        if let jmespath::Variable::String(str) = &*args[0] {
            let mut res = String::new();
            if let jmespath::Variable::String(re_str) = &*args[1] {
                if let jmespath::Variable::String(newval) = &*args[2] {
                    match Regex::new(re_str) {
                        Ok(re) => {
                            res = re.replace(str.as_str(), newval.as_str()).to_string();
                        }
                        Err(err) => {
                            return Err(JmespathError::new(
                                re_str,
                                0,
                                ErrorReason::Parse(format!("Invalid regular expression: {}", err)),
                            ));
                        }
                    }
                }
            }
            trace!("jmespath resub() result: {}", &res);
            return Ok(Arc::new(jmespath::Variable::String(res)));
        }

        Ok(Arc::new(jmespath::Variable::Null))
    });

    Box::new(CustomFunction::new(fn_signature, fn_impl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resub_should_handle_null_input() {
        let runtime = init_runtime();

        // Parse some JSON data into a JMESPath variable
        let json_str = r#"
        {
            "groups":["a", "b"]
        }
        "#;
        let jmespath_var = jmespath::Variable::from_json(json_str).unwrap();

        // Create an expression that should yield null when evaluated
        let null_expr = "groups[?@ == 'idontexist'] | [0]";
        let should_yield_null = runtime.compile(null_expr).unwrap();
        let result = should_yield_null.search(&jmespath_var).unwrap();
        assert_eq!(jmespath::Variable::Null, *result);

        // Now use that expression as input to the resub() function and verify that it returns null too
        let should_also_yield_null = runtime
            .compile(&format!("resub({}, '^.+$', 'admin')", null_expr))
            .unwrap();
        let result = should_also_yield_null.search(&jmespath_var).unwrap();
        assert_eq!(jmespath::Variable::Null, *result);
    }

    #[test]
    fn resub_should_return_error_when_given_an_invalid_regex() {
        let runtime = init_runtime();

        // an opening square bracket without matching closing square bracket is an invalid regular expression
        let should_also_yield_null = runtime.compile("resub('dummy input', '[', 'admin')").unwrap();

        // Parse some JSON data into a JMESPath variable
        let json_str = r#"
        {
            "groups":["a", "b"]
        }
        "#;
        let jmespath_var = jmespath::Variable::from_json(json_str).unwrap();

        assert!(should_also_yield_null.search(&jmespath_var).is_err());
    }
}
